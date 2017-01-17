import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

#Validation for information using regular expressions
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

##### User code
#Used to help hash password
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

#Hashes password
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

#Validates passowrd
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

#Class to store user entities
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        user = cls.all().filter('name =', name).get()
        return user

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        user = cls.by_name(name)
        if user and valid_pw(name, pw, user.pw_hash):
            return user

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

#Class to store post entities
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    user = db.StringProperty(required = True)
    likes = db.StringListProperty(required = True,  default = None)
    comments = db.StringListProperty(required = True, default = None)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

#Entity to store all differnet comments
class Comment(db.Model):
    user = db.StringProperty(required = True)
    comment = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

#Used to help hash
secret = 'TheseViolentDelightsHaveViolentEnds'

#Returns string that has hash and orgininal value
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#Used to help render template
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

#Handler class that helps renders all pages
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

##### blog code
#Class for landing page
class MainPage(BlogHandler):
    def get(self):
        if self.user:
            self.redirect('/blog')
        else:
            self.render("base.html")

    def post(self):
        login = self.request.POST.get('login')
        create = self.request.POST.get('create')
        error = ''

        #For when user is logging in
        if login != None:
            username = self.request.get('username')
            password = self.request.get('password')

            user = User.login(username, password)
            if user:
                self.login(user)
                self.redirect('/blog')
            else:
                msg = 'Invalid login'
                self.render('base.html', error = msg)

        #For when user is signing up for first time
        elif create != None:
            #Checks for various possible errors
            have_error = False
            self.username = self.request.get('newusername')
            self.password = self.request.get('newpassword')
            self.verify = self.request.get('verify')
            self.email = self.request.get('email')

            params = dict(username = self.username,
                          email = self.email)

            if not valid_username(self.username):
                error += "That's not a valid username.\n"
                have_error = True

            if not valid_password(self.password):
                error += "That wasn't a valid password.\n"
                have_error = True
            elif self.password != self.verify:
                error += "Your passwords didn't match.\n"
                have_error = True

            if not valid_email(self.email):
                error += "That's not a valid email.\n"
                have_error = True

            #If there was an error a message appears, else
            #we check if that user already exists
            if have_error:
                self.render('base.html', error = error)
            else:
                #Renders error when the user already appears
                user = User.by_name(self.username)
                if user:
                    error = 'That user already exists.'
                    self.render('base.html', error = error)
                else:
                    #Only login and creates new user if the user is unique
                    user = User.register(self.username, self.password, self.email)
                    user.put()

                    self.login(user)
                    self.redirect('/blog')

#Class for blog page (main page)
class BlogFront(BlogHandler):
    def get(self):
        #Only goes to blog when the person is a valid user
        if self.user:
            posts = greetings = Post.all().order('-created')
            self.render('blog.html', posts = posts, username = self.user.name)
        else:
            self.redirect('/')
    def post(self):
        #Only goes to blog when the person is a valid user
        if not self.user:
            error = 'That user already exists.'
            self.render('base.html', error = error)

        #Checks to see which button was pressed
        like = self.request.POST.get('like')
        unlike = self.request.POST.get('unlike')
        delete = self.request.POST.get('delete')
        save = self.request.POST.get('save')

        #Bases action bases on which button was pressed. Button returns the post key
        #so we can find post by searching the key
        if like != None:
            post = db.get(like)

            #Uses if condition in case user presses button twice before loading
            if self.user.name not in post.likes:
                post.likes.append(self.user.name)
                post.put()
        elif unlike != None:
            post = db.get(unlike)

            #Uses if condition in case user presses button twice before loading
            if self.user.name in post.likes:
                post.likes.remove(self.user.name)
                post.put()
        elif delete != None:
            post = db.get(delete)
            if post:
                post.delete()
        elif save != None:
            post = db.get(save)
            newsubject = self.request.get('newsubject')
            newcontent = self.request.get('newcontent')

            #Only updates subject or content if they are not blank. If it is blank we
            #keep the old subject/comment
            if newsubject:
                post.subject = newsubject
            if newcontent:
                post.content = newcontent
            post.put()

        #Sleep before redirecting because I ran into the problem that the page reloaded
        #before the entity was stored in database
        time.sleep(0.1)
        self.redirect("/blog")

class NewPost(BlogHandler):
    def get(self):
        #Only renders if the person is an actual user
        if self.user:
            self.render("newpost.html", username = self.user.name)
        else:
            self.redirect("/")

    def post(self):
        #Again redirects if it is not a user
        if not self.user:
            self.redirect('/')

        #Sees what button is pressed
        cancel = self.request.POST.get('cancel')
        post = self.request.POST.get('post')

        #Bases action on which button is pressed
        if cancel != None:
            self.redirect('/blog')
        elif post != None:
            subject = self.request.get('subject')
            content = self.request.get('content')

            #Only creates new post when there is a subject and content for
            if subject and content:
                p = Post(parent = blog_key(), subject=subject, content=content, user=self.user.name)
                p.put()
                time.sleep(.1)
                self.redirect('/blog')

            #Renders error message when there are either not a subject or content
            else:
                error = "subject and content, please!"
                self.render("newpost.html", username=self.user.name, subject=subject, content=content, error=error)

#Class for Post page
class PostPage(BlogHandler):
    def get(self, post_id):
        #Again only renders when it is a user
        if self.user:
            #Get the post to render
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            #Converts all of the comments into actual comment objects since
            #all that is sotred in post.comments are the keys for the comments
            #associated with the post
            comments = []
            commentkeys = post.comments
            for commentkey in commentkeys:
                comments.append(db.get(commentkey))

            if not post:
                self.error(404)
                return

            self.render("permalink.html", post=post, username=self.user.name, comments=comments)
        else:
            self.redirect("/")

    def post(self, post_id):
        #Redirects when person is not a user
        if not self.user:
            self.redirect('/')

        #Get the post information
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        #Get information to see what button has been posted
        postcomment = self.request.POST.get('postcomment')
        editcomment = self.request.POST.get('editcomment')
        deletecomment = self.request.POST.get('deletecomment')

        #Performs different information depedning on button
        if editcomment != None:
            #Finds comment since all buttons give comment key and updates
            #the comment
            newcomment = self.request.get('newcomment')
            if newcomment:
                c = db.get(editcomment)
                c.comment = newcomment
                c.put()
            time.sleep(0.1)
            self.redirect('/blog/%s' % str(post.key().id()))
        elif deletecomment != None:
            #Finds comment same as edit, but deletes instead
            c = db.get(deletecomment)
            if c:
                #Also have to delete comment key  from the post.comments
                c.delete()
                post.comments.remove(str(c.key()))
                post.put()
            time.sleep(0.1)
            self.redirect('/blog/%s' % str(post.key().id()))
        elif postcomment != None:
            comment = self.request.get('comment')

            #Only creates comments when there is content to comment
            if comment:
                c = Comment(parent = blog_key(), comment=comment, user=self.user.name)
                c.put()
                post.comments.append(str(c.key()))
                post.put()
                time.sleep(0.1)
                self.redirect('/blog/%s' % str(post.key().id()))

            #Renders error message when there is no content
            else:
                comments = []
                commentkeys = post.comments
                for commentkey in commentkeys:
                    comments.append(db.get(commentkey))
                error = "Comment needs to have content"
                self.render("permalink.html", post=post, username=self.user.name, comments=comments, error=error)

#Class for when user logs out
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)', PostPage),
                               ('/logout', Logout),
                               ],
                              debug=True)
