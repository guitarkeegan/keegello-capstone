from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from forms import LoginForm, KanbanCardForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
Bootstrap(app)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///keegello.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)

    cards = relationship("Card", back_populates="card_participant")


class Card(db.Model):
    __tablename__ = "cards"
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(80), nullable=False)
    priority = db.Column(db.String(80), nullable=False)
    task = db.Column(db.String(250), nullable=False)
    description = db.Column(db.String(500), nullable=False)

    participant_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    card_participant = relationship("User", back_populates="cards")


db.create_all()


@app.route("/")
def homepage():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("The email is not in our records. Try again or create new account.")
            return redirect(url_for("login"))
        elif not check_password_hash(user.password, password):
            flash("Password is incorrect, please try again.")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("main_app"))
    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("homepage"))


@app.route("/signup", methods=["GET", "POST"])
def sign_up():
    form = LoginForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("You've already signed up. Login instead!")
            return redirect(url_for("login"))

        hash_and_salted_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            email=form.email.data,
            password=hash_and_salted_password,
            name=form.name.data
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("main_app"))
    return render_template("sign-up.html", form=form)


@app.route("/main-app", methods=["GET", "POST"])
@login_required
def main_app():
    if not current_user.is_authenticated:
        flash("You must login to use the kanban.")
        return redirect(url_for("login"))
    all_cards = Card.query.filter_by(participant_id=current_user.id).all()
    users = User.query.get(current_user.id)
    new_card_form = KanbanCardForm()
    if new_card_form.validate_on_submit():
        card = Card(
            category=new_card_form.category_select.data,
            priority=new_card_form.priority.data,
            task=new_card_form.task.data,
            description=new_card_form.description.data,
            participant_id=current_user.id
        )
        db.session.add(card)
        db.session.commit()
        return redirect(url_for("main_app"))
    return render_template("app.html", form=new_card_form, cards=all_cards, users=users)


@app.route("/delete/<int:card_id>")
@login_required
def delete_card(card_id):
    card_to_delete = Card.query.get(card_id)
    db.session.delete(card_to_delete)
    db.session.commit()
    return redirect(url_for("main_app"))


@app.route("/edit-card/<int:card_id>", methods=["GET", "POST"])
@login_required
def edit_card(card_id):
    card_to_edit = Card.query.get(card_id)
    edit_form = KanbanCardForm(
        category_select=card_to_edit.category,
        priority=card_to_edit.priority,
        task=card_to_edit.task,
        description=card_to_edit.description
    )
    if edit_form.validate_on_submit():
        card_to_edit.category = edit_form.category_select.data
        card_to_edit.priority = edit_form.priority.data
        card_to_edit.task = edit_form.task.data
        card_to_edit.description = edit_form.description.data
        db.session.commit()
        return redirect(url_for("main_app"))
    return render_template("edit.html", form=edit_form)


if __name__ == "__main__":
    app.run(debug=False)
