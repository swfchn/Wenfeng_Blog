import wtforms.validators
from flask import Flask, render_template, redirect, url_for, flash,abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy import ForeignKey
from forms import CreatePostForm,RegisterForm,LoginForm,CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)
##CONNECT TO DB  if provided, but if it's None (e.g. when running locally) then we can provide sqlite:///blog.db as the alternative.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Enable login https://flask-login.readthedocs.io/en/latest/
login_manager = LoginManager()
login_manager.init_app(app)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("User", back_populates="posts")
    author_id = db.Column(db.Integer, ForeignKey("user.id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="comment_post")


class User(db.Model,UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(100), unique=True)
    comments = relationship("Comment", back_populates="comment_author")
    posts = relationship("BlogPost", back_populates="author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text,nullable=False)
    author_id = db.Column(db.Integer, ForeignKey('user.id'))
    post_id = db.Column(db.Integer, ForeignKey("blog_posts.id"))
    comment_author = relationship("User", back_populates="comments")
    comment_post = relationship("BlogPost", back_populates="comments")

db.create_all()

def admin_required(f):
    # wraps is for keeping the original funciton's name __name__
    @wraps(f)
    def decorated_function(*args,**kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id !=1:
            return abort(403)
        return f(*args,**kwargs)
    return decorated_function

# enable login function to provide user_loader callback
@login_manager.user_loader
def load_user(user_id):
    print(type(user_id))
    return User.query.get(int(user_id))

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm()
    # validation happens below
    if form.validate_on_submit():
        email_to_register = form.email.data
        if User.query.filter_by(email=email_to_register).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))
        else:
            salted_hash_pwd = generate_password_hash(
                form.password.data,
                'pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                name=form.name.data,
                email=form.email.data,
                password=salted_hash_pwd,
            )
            db.session.add(new_user)
            db.session.commit()
            # This line will authenticate the user with Flask-Login
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_email =form.email.data
        user_instance = User.query.filter_by(email=user_email).first()
        if user_instance:
            hash_salted_pwd = user_instance.password
            if check_password_hash(hash_salted_pwd,form.password.data):
                login_user(user_instance)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Password incorrect. please try again")
                return redirect(url_for('login'))
        else:
            flash("The email does not exist. please try again.")
            return redirect(url_for('login'))

    return render_template("login.html",form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET','POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_input = CommentForm()
    if comment_input.validate_on_submit():
        if current_user.is_authenticated:
            new_comment=Comment(
                comment=comment_input.comment.data,
                comment_author=current_user,
                comment_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
    return render_template("post.html", post=requested_post,form=comment_input)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET','POST'])
@admin_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>")
@admin_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug='True')
