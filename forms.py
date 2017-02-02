from flask_wtf import Form
from wtforms import StringField, TextAreaField, SubmitField, RadioField, PasswordField, SelectField, FileField
from wtforms.validators import (DataRequired, Email, Regexp, ValidationError, Length, EqualTo)

from models import User


def name_exists(form, field):
    if User.select().where(User.username == field.data).exists():
        raise ValidationError('User with that name already exists.')


def email_exists(form, field):
    if User.select().where(User.email == field.data).exists():
        raise ValidationError('User with that email already exists.')


class LoginForm(Form):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])


class RegisterForm(Form):
    username = StringField(
        'Username',
        validators=[
            DataRequired(),
            Regexp(
                r'^[a-zA-Z0-9_]+$',
                message=("Username should be one word, letters, "
                         "numbers, and underscores only.")
            ),
            name_exists
        ]
    )
    email = StringField(
        'Email',
        validators=[
            DataRequired(),
            Email(),
            email_exists
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=2),
            EqualTo('password2', message='Passwords must match')
        ]
    )
    password2 = PasswordField(
        'Confirm Password',
        validators=[DataRequired()]
    )


class EditForm(Form):
    username = StringField(
        'Username',
        validators=[
            Regexp(
                r'^[a-zA-Z0-9_]*$',
                message=("Username should be one word letters, "
                         "numbers, and underscores only.")
            ),
            name_exists
        ]
    )
    email = StringField(
        'Email',
        validators=[
            email_exists
        ]
    )
    password = PasswordField(
        'Confirm password',
        validators=[
            Length(min=6),
            DataRequired()
        ]
    )

class EditPassword(Form):
    confirm_password = PasswordField(
        'Confirm password',
        validators=[DataRequired()]
    )
    new_password = PasswordField(
        'New password',
        validators=[DataRequired(), Length(min=6), EqualTo('confirm_new_password', message='Passwords must match')]
    )
    confirm_new_password = PasswordField(
        'Confirm new password',
        validators=[DataRequired()]
    )


class ChangePassword(Form):
    password = PasswordField(
        'Password',
        validators=[DataRequired(), Length(min=6), EqualTo('password2', message="Passwords must match")]
    )
    password2 = PasswordField(
        'Confirm Password',
        validators=[DataRequired()]
    )


class AdminRegisterForm(RegisterForm):
    roles = SelectField("Roles", coerce=str, choices=[("stageone", "stage one"),
                                          ("stagetwo", "stage two"),
                                          ("stagethree", "stage three"),
                                          ("stagefour", "stage four"),
                                          ("admin", "admin")])


class UploadForm(Form):
    type_choice = RadioField(choices=[('subtitle', 'subtitles'), ('transcript', 'transcripts')])
    directory_choices = SelectField(coerce=int)
    upload = FileField('File', validators=[DataRequired()])
    google_doc = StringField("Google Doc link")


class AdminUploadForm(UploadForm):
    stage_or_archive = SelectField(coerce=str, choices=[("stage", "main stage"),
                                                        ("archive", "archive")])
    button = SubmitField("Submit")


class EmailForm(Form):
    email_message = TextAreaField(validators=[DataRequired()])
