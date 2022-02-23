from flask_wtf import FlaskForm
from wtforms import StringField, validators, EmailField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, Email


class LoginForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = EmailField("Email: ", validators=[DataRequired(), Email(message="Must contain @ and .")])
    password = PasswordField("Password: ", validators=[DataRequired(), Length(min=6, message="Must be at least 6 "
                                                                                             "characters long.")])
    submit = SubmitField("Log me in!")


class KanbanCardForm(FlaskForm):
    category_select = SelectField("Status", choices=["To-do", "In-progress", "Complete"])
    priority = SelectField("Priority", choices=["High", "Medium", "Low"])
    task = StringField("Task Name", validators=[DataRequired()])
    description = StringField("Task Description", validators=[DataRequired()])
    submit = SubmitField("Create Card")
