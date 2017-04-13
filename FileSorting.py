

import os
import json
from shutil import copyfile
from flask import (Flask, render_template, flash, redirect, url_for, g, abort, send_from_directory, request, jsonify)
from flask_login import (LoginManager, login_user, logout_user,
                         login_required, current_user)
from flask_bcrypt import check_password_hash, generate_password_hash
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from threading import Thread
import re
import forms
import models
from models import upload_tables, uploaded_archives, download_tables, download_archives
from decorators import async, role_required, authenticated
from paths import get_path
from filetools import move_file, remove_file, clone_file

# ADD G.USER.HAS_ROLE('ADMIN') TO STAGE CHECK


app = Flask(__name__)


dir_path = os.path.dirname(os.path.realpath(__file__))
sep = os.path.sep

with open('{0}{1}local{1}auth.json'.format(dir_path, sep)) as data_file:
    data = json.load(data_file)
    app.secret_key = data['key']
    sender_email = data['senderEmail']
    receiver = data['receiverEmail']
    app.config["MAIL_USERNAME"] = sender_email
    app.config["MAIL_PASSWORD"] = data["password"]


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
# app.config['MAIL_SUPPRESS_SEND'] = True


mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


UPLOAD_FOLDER = "{0}{1}static{1}uploads{1}".format(dir_path, sep)
archive = 'archive{}'.format(os.path.sep)
archive_path = UPLOAD_FOLDER + archive

STAGE_ONE_UPLOADS = "stageone{}".format(os.path.sep)
STAGE_TWO_UPLOADS = "stagetwo{}".format(os.path.sep)
STAGE_THREE_UPLOADS = "stagethree{}".format(os.path.sep)
STAGE_FOUR_UPLOADS = "stagefour{}".format(os.path.sep)
FINISHED_FILES_UPLOADS = "finishedfiles{}".format(os.path.sep)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'rtf', 'vtt', 'docx'}

TRANSCRIPT_EXTENSIONS = ['doc', 'txt', 'rtf', 'docx']

SUBTITLE_EXTENSIONS = ['vtt']


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


def type_extension_check(filename, filetype):
    extension = filename.rsplit(".", 1)[1]

    if filetype == "subtitle":
        if extension in SUBTITLE_EXTENSIONS:
            return True
        else:
            return False
    else:
        if extension in TRANSCRIPT_EXTENSIONS:
            return True
        else:
            return False


def validate_email(email):
    return re.search(r'^[^\s@]+@[^\s@]+.[^\s@]+$', email)

def restrict_files(file_list):
    if g.user.has_role('admin') or g.user.has_role('superadmin') or g.user.has_role('stagefour'):
        return file_list
    elif g.user.has_role('stagethree'):
        return file_list[:3]
    elif g.user.has_role('stagetwo'):
        return file_list[:2]
    return file_list[:1]


@async
def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_mail(subject, sender, recipients, text_body, html_body=None):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    send_async_email(app, msg)


@app.context_processor
def utility_processor():
    def full_path(string):
        return get_path(string)
    return dict(get_path=full_path)


# structure for populating select field in index function
uploads = {
        1: "stage one",
        2: "stage two",
        3: "stage three",
        4: "stage four",
        5: "finished files"
}

upload_path = {
    "stageone": STAGE_ONE_UPLOADS,
    "stagetwo": STAGE_TWO_UPLOADS,
    "stagethree": STAGE_THREE_UPLOADS,
    "stagefour": STAGE_FOUR_UPLOADS,
    "finishedfiles": FINISHED_FILES_UPLOADS
}

# upload_tables = {
#     "stageone": models.StageOneUpload,
#     "stagetwo": models.StageTwoUpload,
#     "stagethree": models.StageThreeUpload,
#     "stagefour": models.StageFourUpload
# }

# uploaded_archives = {
#     "stageone": models.StageOneArchive,
#     "stagetwo": models.StageTwoArchive,
#     "stagethree": models.StageThreeArchive,
#     "stagefour": models.StageFourArchive
# }


@login_manager.user_loader
def load_user(userid):
    try:
        return models.User.get(models.User.id == userid)
    except models.DoesNotExist:
        return None


@app.before_request
def before_request():
    """Connect to the database before each request."""
    g.db = models.DATABASE
    g.db.connect()
    g.user = current_user


@app.after_request
def after_request(response):
    """Close the database connection after each request."""
    g.db.close()
    return response


@app.route('/register', methods=('GET', 'POST'))
def register():
    form = forms.RegisterForm()
    if form.validate_on_submit():
        user = models.User.create_user(username=form.username.data.strip(),
                                       email=form.email.data.strip(), password=form.password.data.strip())
        flash("Thank you for registering an admin will need to confirm, in the mean time please confirm your email",
              "success")
        token = user.generate_email_token().decode('ascii')
        # ADD EMAIL FUNCTIONS !!!!!!
        send_mail("confirm email", sender_email, [user.email],
                  render_template('confirm.txt', user=user, token=token),
                  render_template("confirm_email.html", user=user, token=token))
        send_mail('user registered', sender_email, [receiver],
                  render_template('admin/confirm_user.txt', user=user,
                                  token=token))
        return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route('/confirm/<token>', methods=('GET', 'POST'))
def confirm_email(token):
    user = models.User.verify_email_token(token)
    if user:
        user.email_confirmed = True
        user.save()
        flash("Email confirmed!", "success")
    return redirect(url_for('index'))


@app.route('/sendmail', methods=('GET',))
def send_confirm_email():
    token = g.user.generate_email_token().decode('ascii')
    print(g.user.username + " " + "mail sending")
    send_mail("Confirm EMail", sender_email, [g.user.email],
              render_template('confirm.txt', user=g.user, token=token),
              render_template('confirm_email.html', user=g.user, token=token))
    flash("Email sent", "success")
    return redirect(url_for('index'))


@app.route('/reset', methods=('GET', 'POST'))
@app.route('/reset/<token>', methods=('GET', 'POST'))
def reset_password(token=None):

    if token:
        form = forms.ChangePassword()
        user = models.User.verify_email_token(token)

        if user:
            login_user(user)
            return render_template('change_pass.html', form=form)

    if request.method == 'POST':
        info = request.json
        user = models.User.get_user(email=info['email'].strip())
        if user:
            token = user.generate_email_token().decode('ascii')
            send_mail("Reset Password", sender_email, [user.email],
                      render_template("resetpass.txt", token=token))
            return jsonify(message="success"), 200
        else:
            return jsonify(message="error"), 200


@app.route('/changepass', methods=('POST',))
@login_required
def change_password():
    form = forms.ChangePassword()
    if form.validate_on_submit():
        g.user.password = generate_password_hash(form.password.data)
        g.user.save()
        return redirect(url_for('index'))
    return render_template('change_pass.html', form=form)



@app.route('/admin/ajaxtest', methods=('POST',))
@app.route('/admin/ajaxtest/<thing>', methods=('POST',))
def ajax_test(thing=None):
    print(request.json)
    info = request.json
    if thing:
        user = models.User.get_user(username=request.json)
        user.admin_confirmed = not user.admin_confirmed
        user.save()
    user = models.User.get_user(username=info['name'])

    return jsonify(user.username), 200


@app.route('/update', methods=('GET', 'POST'))
@login_required
def edit_user():
    form = forms.EditForm()
    password_form = forms.EditPassword()
    if form.validate_on_submit():
        user = models.User.get_user(username=g.user.username)
        if check_password_hash(user.password, form.password.data):
            if not form.username.data and not form.email.data:
                flash("No information submitted", "warning")
                return redirect(url_for('edit_user'))
            elif form.username.data and form.email.data and validate_email(form.email.data):
                user.username = form.username.data.strip()
                user.email = form.email.data.strip()
                user.save()
                flash("Username updated to {}. Email updated to {}".format(form.username.data.strip(),
                                                                           form.email.data.strip()), "success")
                return redirect(url_for('index'))
            elif form.username.data or (form.email.data and validate_email(form.email.data)):
                if form.username.data:
                    user.username = form.username.data
                    user.save()
                else:
                    user.email = form.email.data
                    user.save()
                flash("Username updated to {}".format(form.username.data) if form.username.data else
                      "Email updated to {}".format(form.email.data), "success")
                return redirect(url_for('index'))
        else:
            flash("Your password doesn't match", "danger")
            return redirect(url_for('edit_user'))
    return render_template("edit_info.html", form=form, password_form=password_form)


@app.route('/updatepass', methods=('POST',))
@login_required
def edit_password():
    form = forms.EditPassword()
    if form.validate_on_submit():
        # ACTUALLY CHANGE PASSWORD
        user = models.User.get_user(username=g.user.username)
        user.password = generate_password_hash(form.new_password.data)
        user.save()
        flash("Password updated", "success")
        print("success")
        return redirect(url_for('edit_user', _anchor='profile'))
    flash("Invalid password", "danger")
    return redirect(url_for('edit_user', _anchor='profile'))


@app.route('/login', methods=('GET', 'POST'))
def login():
    form = forms.LoginForm()
    if form.validate_on_submit():
        try:
            user = models.User.get(models.User.email == form.email.data)
        except models.DoesNotExist:
            flash("Your email or password doesn't match!", "danger")
        else:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("You've been logged in", "success")
                return redirect(url_for('index'))
            else:
                flash("Your email or password doesn't match!", "danger")
    return render_template('login.html', form=form)


@app.route('/logout', methods=('GET',))
def logout():
    logout_user()
    flash("You've been logged out!", "success")
    return redirect(url_for('index'))


@app.route('/support', methods=('GET', 'POST'))
@login_required
def support():
    form = forms.EmailForm()
    if form.validate_on_submit():
        print("Formsubbmited")
        send_mail("Support mail", sender=sender_email, recipients=[receiver], text_body=form.email_message.data)
        flash("Message sent", "success")
        return redirect(url_for('index'))
    return render_template('support.html', form=form)



@app.route('/uploads/<path:directory>/<filename>')
@app.route('/uploads/<path:directory>/<filename>/<int:version>')
def downloads(directory, filename, version=None):
    # gets sub directory from full directory path
    # example 'C:\\PycharmProjects\\FileSorting\\static\\uploads\\stageoneuploads\\'
    # ['C:', 'PycharmProjects', 'FileSorting', 'static', 'uploads', 'stageoneuploads', '']
    # second to last = sub_directory
    print(directory)
    sub_directory = directory.split('{}'.format(sep))[-1 if "/" in directory else -2]
    print(directory.rsplit('{}'.format(sep), 1))
    print(sub_directory)
    print(filename)
    print(UPLOAD_FOLDER)
    print(archive_path)

    if directory.split('{}'.format(sep))[-2] == "archive":
        file = uploaded_archives[sub_directory].get_archive_file(filename, version)
        file.worked_on = True
        file.save()

        file_name = "[{}]{}".format(version, filename)
        try:
            other_file = upload_tables[sub_directory].get(
                (upload_tables[sub_directory].file_name.startswith(file.file_name[:8])) &
                (~(upload_tables[sub_directory].file_type)) &
                (~(upload_tables[sub_directory].worked_on))
            )
        except models.DoesNotExist:
            pass
        else:
            other_file.worked_on = True
            other_file.save()
        download_archives[sub_directory].create_entry(g.user._get_current_object(), file)
        return send_from_directory("{}{}".format(archive_path,upload_path[sub_directory]), "[{}]{}".format(version,
                                                                                                           filename))
    else:
        file = upload_tables[sub_directory].get(upload_tables[sub_directory].file_name == filename)
        file.worked_on = True
        file.save()
        try:
            other_file = upload_tables[sub_directory].get(
                (upload_tables[sub_directory].file_name.startswith(file.file_name[:8])) &
                (~(upload_tables[sub_directory].file_type)) &
                (~(upload_tables[sub_directory].worked_on))
            )
        except models.DoesNotExist:
            pass
        else:
            other_file.worked_on = True
            other_file.save()
        download_tables[sub_directory].create_entry(g.user._get_current_object(), file)
        return send_from_directory("{}{}".format(UPLOAD_FOLDER,upload_path[sub_directory]), filename,
                                   attachment_filename=filename, as_attachment=True)


@app.route('/getstarted', methods=('GET',))
def get_started_files():
    audio = models.GetStarted.select().where((models.GetStarted.file_type == "Audio") &
                                             (models.GetStarted.worked_on == False))
    video = models.GetStarted.select().where((models.GetStarted.file_type == "Video") &
                                             (models.GetStarted.worked_on == False))
    all_files = [x for x in video] + [x for x in audio]
    return render_template("get_started.html", audio=audio, video=video, all_files=all_files)


@app.route('/files', methods=('GET',))
@login_required
@authenticated
def files():
    stage_one = models.StageOneUpload.select().where(models.StageOneUpload.worked_on == False).order_by('-id')
    stage_two = models.StageTwoUpload.select().where(models.StageTwoUpload.worked_on == False).order_by('-id')
    stage_three = models.StageThreeUpload.select().where(models.StageThreeUpload.worked_on == False).order_by('-id')
    stage_four = models.StageFourUpload.select().where(models.StageFourUpload.worked_on == False).order_by('-id')
    stage_one_google_doc = models.StageOneUpload.has_google_doc()
    stage_two_google_doc = models.StageTwoUpload.has_google_doc()
    stage_three_google_doc = models.StageThreeUpload.has_google_doc()
    stage_four_google_doc = models.StageFourUpload.has_google_doc()

    stage_one_path = UPLOAD_FOLDER + upload_path["stageone"]
    stage_two_path = UPLOAD_FOLDER + upload_path["stagetwo"]
    stage_three_path = UPLOAD_FOLDER + upload_path["stagethree"]
    stage_four_path = UPLOAD_FOLDER + upload_path["stagefour"]
    all_stages = [('Stage One', stage_one), ('Stage Two', stage_two),
                  ('Stage Three', stage_three), ('Stage Four', stage_four)]
    all_stages = restrict_files(all_stages)

    return render_template('files.html', stage_one=stage_one, stage_two=stage_two,
                           stage_three=stage_three, stage_four=stage_four,
                           path_one=stage_one_path, path_two=stage_two_path,
                           path_three=stage_three_path, path_four=stage_four_path,
                           stage_one_doc=stage_one_google_doc, stage_two_doc=stage_two_google_doc,
                           stage_three_doc=stage_three_google_doc, stage_four_doc=stage_four_google_doc,
                           all_stages=all_stages)


def get_choices(form):
    """
    sets choices based on role of user

    has_role('stage_two') sets choices to the first two items in uploads
    :param form:
    :return:
    """
    try:
        if g.user.has_role('stagefour') or g.user.has_role('admin') or g.user.has_role('superadmin'):
            form.directory_choices.choices = [(key, value) for key, value in uploads.items()]
        elif g.user.has_role('stagethree'):
            form.directory_choices.choices = [(key, value) for key, value in uploads.items()][:3]
        elif g.user.has_role('stagetwo'):
            form.directory_choices.choices = [(key, value) for key, value in uploads.items()][:2]
        else:
            form.directory_choices.choices = [(key, value) for key, value in uploads.items()][0:1]
    except AttributeError:
        pass


# @app.route('/', methods=('GET', 'POST'))
# def index():
#     form = forms.UploadForm()
#     get_choices(form)
#     video_files = models.GetStarted.random_records("Video", 5)
#     audio_files = models.GetStarted.random_records("Audio", 5)
#
#     if form.validate_on_submit():
#         choice = form.directory_choices.data
#         file_type = form.type_choice.data
#
#         # Gets sub directory and removes whitespace " stage one " becomes " stageone "
#         path = uploads[choice].replace(" ", "")
#
#         if allowed_file(form.upload.data.filename):
#             filename = secure_filename(form.upload.data.filename)
#             try:
#                 # models.Uploads.create_stage_entry(uploaded_by=g.user._get_current_object(), uploaded_to=choice,
#                 #                                   file_name=filename)
#                 uploaded_file = upload_tables[path].create_stage_entry(uploaded_by=g.user._get_current_object(),
#                                                                        file_name=filename, file_type=file_type)
#                 # Get part of file_name to check for other files with same part of file_name
#                 uploaded_file_name = uploaded_file.file_name.split('.')[0][:8]
#             except models.IntegrityError:
#                 flash("A file with that name already exists!", "danger")
#                 file = upload_tables[path].get_file(filename, file_type=file_type)
#                 print(file.file_name if file else "None")
#                 if file and file.uploaded_by_id == g.user.id:
#                     flash("You've uploaded this file already!", "warning")
#                     return redirect(url_for('index'))
#
#                 try:
#                     # Try to get files previous versions
#                     prev_version = uploaded_archives[path].select().where((uploaded_archives[path].file_name == filename) &
#                                                                           (uploaded_archives[path].file_type == file_type))
#                 except models.DoesNotExist:
#                     # Creates new entry in table archive for file that doesn't exist and saves file in folder
#                     version = 1
#                     uploaded_archives[path].create_archive_entry(uploaded_by=g.user._get_current_object(),
#                                                                file_name=filename, version=version, file_type=file_type)
#                     form.upload.data.save("{}\\archive\{}\[{}]{}".format(UPLOAD_FOLDER, path, version, filename))
#                     return redirect(url_for('index'))
#                 else:
#                     try:
#                         uploaded_archives[path].get((uploaded_archives[path].file_name == filename) &
#                                                     (uploaded_archives[path].file_type == file_type) &
#                                                     (uploaded_archives[path].uploaded_by_id == g.user.id))
#                     except models.DoesNotExist:
#                         # Creates new entry in table archive for file that does exist and saves file in folder
#                         version = prev_version.count() + 1
#                         uploaded_archives[path].create_archive_entry(uploaded_by=g.user._get_current_object(),
#                                                                      file_name=filename,
#                                                                      version=version, file_type=file_type)
#                         form.upload.data.save("{}\\archive\{}\[{}]{}".format(UPLOAD_FOLDER, path, version, filename))
#                         return redirect(url_for('index'))
#                     else:
#                         flash("error message here", "danger")
#                         return redirect(url_for('index'))
#             else:
#                 try:
#                     # try to get any other file in the same stage that contains uploaded_file_name and is the
#                     # opposite file_type and is worked on already
#                     upload_tables[path].get(
#                         (upload_tables[path].file_name.startswith(uploaded_file_name)) &
#                         (~(upload_tables[path].file_type == uploaded_file.file_type)) &
#                         (upload_tables[path].worked_on)
#                     )
#                 except models.DoesNotExist:
#                     # Creates entry in main files and saves in folder
#                     form.upload.data.save("{}{}\{}".format(UPLOAD_FOLDER, path, filename))
#                 else:
#                     uploaded_file.worked_on = True
#                     uploaded_file.save()
#
#                     # Creates entry in main files and saves in folder
#                     form.upload.data.save("{}{}\{}".format(UPLOAD_FOLDER, path, filename))
#                 return redirect(url_for('index'))
#         else:
#             flash("Please enter correct file name", "danger")
#     return render_template('index.html', form=form, video_files=video_files, audio_files=audio_files)

# new index

@app.route('/', methods=('GET', 'POST'))
def index():
    form = forms.UploadForm()
    get_choices(form)
    video_files = models.GetStarted.random_records("Video", 5)
    audio_files = models.GetStarted.random_records("Audio", 5)
    print(dir_path.split("\\"))

    if form.validate_on_submit():
        directory_choice = form.directory_choices.data
        file_type = form.type_choice.data
        # Gets sub directory and removes whitespace " stage one " becomes " stageone "
        path = uploads[directory_choice].replace(" ", "")

        if allowed_file(form.upload.data.filename):
            filename = secure_filename(form.upload.data.filename)
            no_extension = form.upload.data.filename.rsplit('.', 1)[0]
            # check for file type with correct extension
            if not type_extension_check(filename, file_type):
                flash("File extension doesn't match file type", "danger")
                return render_template('index.html', form=form, video_files=video_files, audio_files=audio_files)

            if path == "finishedfiles":
                try:
                    finished_file = models.FinishedFile.create(
                        uploaded_by=g.user._get_current_object(),
                        file_name=filename,
                        file_type=file_type
                    )
                except models.IntegrityError:
                    flash("File exists", "danger")
                else:
                    flash("File uploaded", "success")
                    form.upload.data.save('{}{}{}'.format(UPLOAD_FOLDER, upload_path[path], filename))
                    if form.google_doc:
                        finished_file.google_docs = form.google_doc
                        finished_file.save()
                    if form.amara.data:
                        finished_file.amara = form.amara.data
                        finished_file.save()
                    models.mark_complete(finished_file.file_name)

                return redirect(url_for('admin_index'))

            # check if user has uploaded file already
            if g.user.has_uploaded(path, filename, file_type):
                flash("You've already uploaded this file!", "warning")
                return redirect(url_for("index"))

            # check if file exists
            file = models.file_exists(path, filename, file_type)
            if file:
                # if file exists upload to archive
                files = models.file_in_archive(path, filename, file_type)
                created_file = uploaded_archives[path].create_archive_entry(
                    uploaded_by=g.user._get_current_object(),
                    file_name=filename,
                    version=files.count() + 1,
                    file_type=file_type
                )
                if form.google_doc.data:
                    created_file.google_doc = form.google_doc.data
                    created_file.save()
                # actually upload file
                send_mail("User uploaded", sender_email, [receiver], "user uploaded file to archive")
                form.upload.data.save("{}{}[{}]{}".format(archive_path, upload_path[path], files.count(), filename))
                return redirect(url_for('index'))

            opposite_file = [path, filename, file_type]
            # create entry in main table
            created_file = upload_tables[path].create_stage_entry(
                uploaded_by=g.user._get_current_object(),
                file_name=filename,
                file_type=file_type,
                worked_on=models.opposite_file_workedon(*opposite_file)
            )
            started_file = models.GetStartedDownloads.in_get_started_downloads(no_extension)
            if started_file:
                started_file.on_stage = True
                started_file.save()
            if form.google_doc.data:
                created_file.google_docs = form.google_doc.data
                created_file.save()
            if form.amara.data:
                created_file.amara = form.amara.data
                created_file.save()
            # actually upload file
            send_mail("User uploaded", sender_email, [receiver],
                      render_template('admin/email.txt', user=g.user._get_current_object(),
                                      message='uploaded {} to {}'.format(created_file.file_name,path)))
            form.upload.data.save("{}{}{}".format(UPLOAD_FOLDER, upload_path[path],filename))
            flash("File uploaded", "success")
            return redirect(url_for('index'))

    return render_template('index.html', form=form, video_files=video_files, audio_files=audio_files)

# Admin views


@app.route('/admin/', methods=('GET', 'POST'))
@login_required
@authenticated
@role_required(["admin", "superadmin"])
def admin_index():
    unconfirmed_users = models.unconfirmed_users()
    form = forms.AdminUploadForm()
    form.directory_choices.choices = [(key, value) for key, value in uploads.items()]
    if form.validate_on_submit():
        directory_choice = form.directory_choices.data
        tables = form.stage_or_archive.data
        file_type = form.type_choice.data

        # Gets sub directory and removes whitespace " stage one " becomes " stageone "
        path = uploads[directory_choice].replace(" ", "")

        if allowed_file(form.upload.data.filename):
            filename = secure_filename(form.upload.data.filename)
            print(form.upload.data.filename)
            no_extension = form.upload.data.filename.rsplit('.', 1)[0]

            # check for file type with correct extension
            if not type_extension_check(filename, file_type):
                flash("File extension doesn't match file type", "danger")
                return render_template('admin/home.html', unconfirmed_users=unconfirmed_users, form=form)

            if path == "finishedfiles":
                try:
                    finished_file = models.FinishedFile.create(
                        uploaded_by=g.user._get_current_object(),
                        file_name=filename,
                        file_type=file_type
                    )
                except models.IntegrityError:
                    flash("File exists", "danger")
                else:
                    flash("File uploaded", "success")
                    form.upload.data.save('{}{}{}'.format(UPLOAD_FOLDER, upload_path[path], filename))
                    if form.google_doc:
                        finished_file.google_docs = form.google_doc
                        finished_file.save()
                    if form.amara.data:
                        finished_file.amara = form.amara.data
                        finished_file.save()
                    models.mark_complete(finished_file.file_name)

                return redirect(url_for('admin_index'))

            # check if user has uploaded file already
            if g.user.has_uploaded(path, filename, file_type):
                flash("You've already uploaded this file!", "warning")
                return redirect(url_for("admin_index"))

            if tables == "stage":
                # check if file exists
                file = models.file_exists(path, filename, file_type)
                if file:
                    # do archive check for filename with person
                    if models.file_in_archive(path, filename, file_type, uploaded_by=g.user._get_current_object()):
                        print("you've uploaded a file already!")
                    else:
                        files = models.file_in_archive(path, filename, file_type)
                        created_file = uploaded_archives[path].create_archive_entry(
                            uploaded_by=g.user._get_current_object(),
                            file_name=filename,
                            version=files.count()+1,
                            file_type=file_type
                        )
                        if form.google_doc.data:
                            created_file.google_doc = form.google_doc.data
                            created_file.save()
                        # actually upload file
                        form.upload.data.save("{}{}[{}]{}".format(archive_path, upload_path[path], files.count(), filename))
                        return redirect(url_for('admin_index'))
                else:
                    opposite_file = [path, filename, file_type]
                    # create entry in main table
                    created_file = upload_tables[path].create_stage_entry(
                        uploaded_by=g.user._get_current_object(),
                        file_name=filename,
                        file_type=file_type,
                        worked_on=models.opposite_file_workedon(*opposite_file)
                    )

                    started_file = models.GetStartedDownloads.in_get_started_downloads(no_extension)
                    print(started_file)
                    if started_file:
                        started_file.on_stage = True
                        started_file.save()
                    if form.google_doc.data:
                        created_file.google_docs = form.google_doc.data
                        created_file.save()
                    if form.amara.data:
                        created_file.amara = form.amara.data
                        created_file.save()
                    # actually upload file
                    form.upload.data.save("{}{}{}".format(UPLOAD_FOLDER, upload_path[path], filename))
                    return redirect(url_for('admin_index'))
            if tables == "archive":
                if models.file_in_archive(path, filename, file_type, uploaded_by=g.user._get_current_object()) or \
                        models.file_exists(path, filename, file_type, g.user._get_current_object()):
                    print("you've uploaded a file already!")
                else:
                    files = models.file_in_archive(path, filename, file_type)
                    version = files.count() + 1
                    created_file = uploaded_archives[path].create_archive_entry(
                        uploaded_by=g.user._get_current_object(),
                        file_name=filename,
                        version=version,
                        file_type=file_type
                    )
                    if form.google_doc.data:
                        created_file.google_docs = form.google_doc.data
                        created_file.save()
                    if form.amara.data:
                        created_file.amara = form.amara.data
                        created_file.save()
                    # actually upload file
                    form.upload.data.save("{}{}[{}]{}".format(archive_path,
                                                              upload_path[path], version, filename))
                    return redirect(url_for('admin_index'))

    return render_template('admin/home.html', form=form, unassigned_users=unconfirmed_users)


@app.route('/admin/users', methods=('GET', 'POST'))
@app.route('/admin/users/<int:id>', methods=('GET',))
@login_required
@authenticated
def users(id=None):
    if id:
        user = models.User.get_user(id)
        # files = user.get_files()
        # return render_template('admin/user.html', user=user, stage_one_files=files[0],
        #                        stage_two_files=files[1],
        #                        stage_three_files=files[2],
        #                        stage_four_files=files[3])
        if not user:
            abort(404)
        all_files = user.all_records()
        get_started = models.GetStartedDownloads.select().where(
            models.GetStartedDownloads.user == g.user._get_current_object()
        )
        return render_template('admin/user.html', user=user, all_files=all_files, get_started=get_started)
                               # # stage 1-4
                               # stage_one_files=all_files['stage'][0],
                               # stage_two_files=all_files['stage'][1],
                               # stage_three_files=all_files['stage'][2],
                               # stage_four_files=all_files['stage'][3],
                               # # stage downloads 1-4
                               # stage_one_downloads=all_files['stageDownload'][0],
                               # stage_two_downloads=all_files['stageDownload'][1],
                               # stage_three_downloads=all_files['stageDownload'][2],
                               # stage_four_downloads=all_files['stageDownload'][3],
                               # # archive 1-4
                               # stage_one_archive=all_files['archive'][0],
                               # stage_two_archive=all_files['archive'][0],
                               # stage_three_archive=all_files['archive'][0],
                               # stage_four_archive=all_files['archive'][0],
                               # # archive downloads 1-4
                               # stage_one_archive_downloads=all_files['archiveDownload'][0],
                               # stage_two_archive_downloads=all_files['archiveDownload'][1],
                               # stage_three_archive_downloads=all_files['archiveDownload'][2],
                               # stage_four_archive_downloads=all_files['archiveDownload'][3])

    users = models.get_users()
    return render_template('admin/users.html', users=users)


@app.route('/admin/deleteuser/<int:userid>', methods=('GET', 'POST'))
@login_required
@role_required(["superadmin"])
def admin_delete_users(userid):
    user = models.User.get_user(userid)
    if not user:
        abort(404)
    if user.has_role("superadmin"):
        flash("Can't delete user", "danger")
        return redirect(url_for('users'))
    user.delete_instance()
    flash("User deleted", "success")
    return redirect(url_for('users'))


@app.route('/admin/required', methods=('GET', "POST"))
@login_required
@role_required(["admin", "superadmin"])
def required_admin():
    return render_template("required_admin.html")


@app.route("/admin/register", methods=('GET', 'POST'))
@login_required
@authenticated
@role_required(["admin", "superadmin"])
def register_users():
    form = forms.AdminRegisterForm()
    if form.validate_on_submit():
        user = models.User.create_user(form.username.data.strip(),
                                form.email.data.strip(),
                                form.password.data,
                                form.roles.data, True)
        flash("User registered", "success")
        token = user.generate_email_token().decode('ascii')
        # add email stuff
        send_mail("You've been registered!", sender_email, [user.email],
                  render_template('confirm.txt', user=user, token=token),
                  render_template('confirm_email.html', user=user, token=token))
        send_mail("{} has registered a user".format(g.user.username), sender_email, [receiver],
                  "{} has been registered with the role {}".format(user.username, form.roles.data))
        return redirect(url_for('register_users'))
    return render_template('admin/register.html', form=form)


@app.route('/admin/confirm/<token>', methods=('GET', 'POST'))
def confirm_user_email(token):
    user = models.User.verify_email_token(token)
    if user:
        user.admin_confirmed = True
        user.save()
        flash("User confirmed!", "success")
    return redirect(url_for('admin_index'))


@app.route('/admin/email', methods=('GET', 'POST'))
@login_required
@authenticated
@role_required(["admin", "superadmin"])
def send_email():
    form = forms.EmailForm()
    if form.validate_on_submit():
        # msg = Message('test subject', sender="mail here", recipients=["mail here"])
        # msg.body = 'text body'
        # msg.html = '<h1>Test HTML</h1> body'
        # mail.send(msg)
        send_mail("test subject", sender_email, [receiver], "test body",
                  "<h1>{}</h1>body".format(form.email_message.data))
        return redirect(location="admin/email")
    return render_template("sendemail.html", form=form)


@app.route("/admin/edit/<int:id>", methods=('GET', 'POST'))
@login_required
@authenticated
@role_required(["superadmin"])
def admin_edit(id):
    form = forms.EditForm()
    user = models.User.get_user(id)
    if form.validate_on_submit():
        if check_password_hash(g.user.password, form.password.data):
            if not form.username.data and not form.email.data:
                flash("No information submitted", "warning")
                return redirect(url_for('edit_user'))
            elif form.username.data and form.email.data and validate_email(form.email.data):
                user.username = form.username.data.strip()
                user.email = form.email.data.strip()
                user.save()
                flash("Username updated to {}. Email updated to {}".format(form.username.data.strip(),
                                                                           form.email.data.strip()), "success")
                return redirect(url_for('admin_index'))
            elif form.username.data or (form.email.data and validate_email(form.email.data)):
                if form.username.data:
                    user.username = form.username.data
                    user.save()
                else:
                    user.email = form.email.data
                    user.save()
                flash("Username updated to {}".format(form.username.data) if form.username.data else
                      "Email updated to {}".format(form.email.data), "success")
                return redirect(url_for('admin_index'))
        else:
            flash("Your password doesn't match", "danger")
            return redirect(url_for('edit_user'))
    else:
        print(form.errors)
    return render_template("admin/edit_info.html", form=form)


@app.route("/admin/editfile/<stage>/<filename>", methods=('GET', 'POST'))
@login_required
@role_required(["admin", "superadmin"])
def admin_edit_file(stage, filename):
    form = forms.EditFile()
    file = upload_tables[stage].get_file(filename)
    if not file:
        abort(404)
    if form.google_doc.data and form.amara.data:
        file.google_docs = form.google_doc.data
        file.amara = form.amara.data
    elif form.google_doc.data:
        file.google_docs = form.google_doc.data
    elif form.amara.data:
        file.amara = form.amara.data
    else:
        return render_template('admin/edit_file.html', stage=stage, filename=filename, form=form)
    file.save()
    return redirect(url_for("admin_files"))



@app.route('/admin/toggleconfirmed/<email>', methods=('GET', 'POST'))
@role_required(["admin", "superadmin"])
def toggle_confirmed(email):
    try:
        user = models.User.get(models.User.email == email)
    except models.DoesNotExist:
        flash("User doesn't exist!", "warning")
        return redirect(url_for('users'))
    if user.has_role('superadmin'):
        return redirect(url_for('users'))
    user.admin_confirmed = not user.admin_confirmed
    flash("User {} is now confirmed".format(user.email) if user.admin_confirmed else
          "User {} is now unconfirmed".format(
        user.email), "success")
    user.save()
    return redirect(url_for('users'))


@app.route('/admin/togglefile', methods=('POST',))
@role_required(["admin", "superadmin"])
def toggle_file():
    info = request.json
    fileName = info['name'].strip()
    fileType = info['fileType'].strip()
    directory = info['directory'].strip()
    file = upload_tables[directory].get_file(fileName, fileType)
    file.worked_on = not file.worked_on
    file.save()
    return jsonify(file.file_name), 200


@app.route('/admin/toggleconfirmed', methods=('POST',))
@login_required
@role_required(["admin", "superadmin"])
def toggle_admin_confirmed():
    info = request.json
    user = models.User.get_user(username=info['name'])
    if user.has_role('superadmin'):
        return redirect(url_for('users'))
    user.admin_confirmed = not user.admin_confirmed
    user.save()
    main_user = g.user.username
    return jsonify(main_user), 200


@app.route('/getstarted', methods=('POST',))
@login_required
@authenticated
def get_started():
    info = request.json
    file = models.GetStarted.get_file(info['fileName'], info['fileType'])
    file.worked_on = True
    file.save()
    new_record = {}
    try:
        new_record = models.GetStarted.random_records(info['fileType'], 1).get()
    except models.DoesNotExist:
        pass
    else:
        new_record = {
            "id": new_record.id,
            "fileName": new_record.file_name,
            "fileLink": new_record.file_link
        }
    models.GetStartedDownloads.create_entry(user=g.user._get_current_object(),
                                            file=file.id)
    send_mail('File info', sender_email, [g.user.email],
              render_template('admin/getstartedemail.txt', file=file))
    send_mail('User getting started', sender_email, [receiver], "{} got started on {}".format(g.user.username,
                                                                                              file.file_link))

    return jsonify(new_record if new_record else "error"), 200


@app.route('/admin/confirmandregister', methods=('POST',))
@role_required(["admin", "superadmin"])
def confirm_assign():
    info = request.json
    user = models.User.get_user(username=info['name'])
    user.admin_confirmed = True
    user.save()
    user.create_role(info['role'])
    return jsonify("success"), 200


@app.route('/admin/assignrole', methods=('POST',))
@role_required(["admin", "superadmin"])
def assign_role():
    info = request.json
    user = models.User.get_user(username=info['name'])
    if user.has_role('superadmin'):
        return redirect(url_for('users'))
    if user.has_any_role():
        user.get_role().delete_instance()
    user.create_role(info['role'])
    user.save()
    return jsonify(info['name'] + " " + info['role']), 200


@app.route('/admin/deleterole', methods=('POST',))
@role_required(["admin", "superadmin"])
def delete_role():
    info = request.json
    user = models.User.get_user(username=info['name'])
    if user.has_role('superadmin'):
        return redirect(url_for('users'))
    user.delete_role()
    user.save()
    return jsonify(info['name']), 200


@app.route('/name', methods=('POST',))
def name_exists():
    name = request.json
    message = ""
    user = models.User.get_user(username=name)
    if user:
        message = "error"
    else:
        message = "success"

    return jsonify(message), 200


@app.route('/email', methods=('POST',))
def email_exists():
    email = request.json
    message = ""
    user = models.User.get_user(email=email)
    if user:
        message = "error"
    else:
        message = "success"
    return jsonify(message), 200


@app.route('/admin/files', methods=('GET', 'POST'))
@login_required
@role_required(["admin", "superadmin"])
def admin_files():
    stage_one = models.StageOneUpload.select().order_by('-id')
    stage_two = models.StageTwoUpload.select().order_by('-id')
    stage_three = models.StageThreeUpload.select().order_by('-id')
    stage_four = models.StageFourUpload.select().order_by('-id')

    stage_one_path = UPLOAD_FOLDER + upload_path["stageone"]
    stage_two_path = UPLOAD_FOLDER + upload_path["stagetwo"]
    stage_three_path = UPLOAD_FOLDER + upload_path["stagethree"]
    stage_four_path = UPLOAD_FOLDER + upload_path["stagefour"]

    all_files = [("Stage One", stage_one), ("Stage Two", stage_two),
                 ("Stage Three", stage_three), ("Stage Four", stage_four)]

    return render_template('admin/adminfiles.html', stage_one=stage_one, stage_two=stage_two,
                           stage_three=stage_three, stage_four=stage_four,
                           path_one=stage_one_path, path_two=stage_two_path,
                           path_three=stage_three_path, path_four=stage_four_path, all_stages=all_files)


@app.route('/admin/downloadlog', methods=('GET',))
@login_required
@role_required(["admin", "superadmin"])
def download_log():
    all_downloads = models.downloads()
    get_started = models.GetStartedDownloads.select()
    return render_template('admin/downloads.html', all_downloads=all_downloads, get_started=get_started)


@app.route('/admin/archive', methods=('GET',))
@login_required
@role_required(["admin", "superadmin"])
def archive_files():
    stage_one = models.StageOneArchive.select().order_by('-version')
    stage_two = models.StageTwoArchive.select().order_by('-version')
    stage_three = models.StageThreeArchive.select().order_by('-version')
    stage_four = models.StageFourArchive.select().order_by('-version')

    stage_one_path = archive_path + upload_path['stageone']
    stage_two_path = archive_path + upload_path['stagetwo']
    stage_three_path = archive_path + upload_path['stagethree']
    stage_four_path = archive_path + upload_path['stagefour']

    all_files = [("Stage One Archive", stage_one), ("Stage Two Archive", stage_two),
                 ("Stage Three Archive", stage_three), ("Stage Four Archive", stage_four)]

    return render_template('admin/archivefiles.html', stage_one=stage_one, stage_two=stage_two,
                           stage_three=stage_three, stage_four=stage_four,
                           path_one=stage_one_path, path_two=stage_two_path,
                           path_three=stage_three_path, path_four=stage_four_path, all_stages=all_files)


@app.route('/admin/delete/<path:directory>/<filename>/<filetype>/', methods=('GET', 'POST'))
@app.route('/admin/delete/<path:directory>/<filename>/<filetype>/<int:version>', methods=('GET', 'POST'))
@role_required(["admin", "superadmin"])
def delete_files(directory, filename, filetype, version=None):
    sub_directory = directory.split('{}'.format(sep))[-1 if "/" in directory else -2]
    # add main stage delete too
    print("delete print")
    print(directory.split(sep))
    print(sep)
    print(directory)
    print(directory.split('{}'.format(sep))[-2])
    if "archive" in directory.split('{}'.format(sep)):
        file = uploaded_archives[sub_directory].get(uploaded_archives[sub_directory].file_name == filename,
                                                    uploaded_archives[sub_directory].file_type == filetype,
                                                    uploaded_archives[sub_directory].version == version)
        os.remove("{}{}[{}]{}".format(archive_path, upload_path[sub_directory], file.version, file.file_name))
        download_entries = download_archives[sub_directory].select().where(
            download_archives[sub_directory].file == uploaded_archives[sub_directory].get_archive_file(filename, version))
        for item in download_entries:
            try:
                item.delete_instance()
            except models.DoesNotExist:
                pass
        file.delete_instance()
    else:
        file = upload_tables[sub_directory].get(upload_tables[sub_directory].file_name == filename,
                                                upload_tables[sub_directory].file_type == filetype)
        download_entries = download_tables[sub_directory].select().where(download_tables[sub_directory].file == upload_tables[sub_directory].get_file(filename))
        for item in download_entries:
            try:
                item.delete_instance()
            except models.DoesNotExist:
                pass
        os.remove("{}{}{}".format(UPLOAD_FOLDER, upload_path[sub_directory], file.file_name))
        file.delete_instance()
    return redirect(url_for('admin_index'))


@app.route('/toarchive/<path:directory>/<filename>/<filetype>', methods=('GET', 'POST'))
@role_required(["admin", "superadmin"])
def to_archive(directory, filename, filetype):
    sub_directory = directory.split('{}'.format(sep))[-1 if "/" in directory else -2]
    file = upload_tables[sub_directory].get_file(filename, filetype)
    file_exists = models.file_in_archive(sub_directory, file.file_name, file.file_type,
                                         uploaded_by=file.uploaded_by)
    if file_exists:
        models.transfer_stage_downloads(sub_directory, file_exists,
                                        [download for download in download_tables[sub_directory].select().where(
                                            download_tables[sub_directory].file == file
                                        )])
        remove_file(UPLOAD_FOLDER+upload_path[sub_directory], file.file_name)
        file.delete_instance()
        return redirect(url_for('admin_files'))
    archive_file = models.file_to_archive(sub_directory, file)
    move_file(
        "{}{}{}".format(UPLOAD_FOLDER, upload_path[sub_directory], file.file_name),
        "{}{}[{}]{}".format(archive_path, upload_path[sub_directory], archive_file.version, archive_file.file_name)
    )
    return redirect(url_for('admin_files'))


@app.route('/fromarchive/<path:directory>/<filename>/<filetype>/<int:version>', methods=('GET', 'POST'))
@role_required(["admin", "superadmin"])
def from_archive(directory, filename, filetype, version):
    sub_directory = directory.split('{}'.format(sep))[-1 if "/" in directory else -2]
    # archive file to move from archive
    transfer_file = uploaded_archives[sub_directory].get_archive_file(filename, version)
    # check if file exists in main stage already
    file_exists = upload_tables[sub_directory].get_file(filename)
    if file_exists:
        # check if stage file exists in archive
        in_archive = models.file_in_archive(sub_directory, file_exists.file_name, file_exists.file_type,
                                            uploaded_by=file_exists.uploaded_by)
        if not in_archive:
            in_archive = models.file_to_archive(sub_directory, file_exists)
            move_file(
                "{}{}{}".format(UPLOAD_FOLDER, upload_path[sub_directory], file_exists.file_name),
                "{}{}[{}]{}".format(archive_path, upload_path[sub_directory],
                                    in_archive.version, in_archive.file_name)
            )
        else:
            models.transfer_stage_downloads(sub_directory, file_exists,
                                            [download for download in download_tables[sub_directory].select().where(
                                                download_tables[sub_directory].file == file_exists
                                            )])
            remove_file(UPLOAD_FOLDER + upload_path[sub_directory], file_exists.file_name)
        file_exists.delete_instance()
    upload_tables[sub_directory].create_stage_entry(uploaded_by=transfer_file.uploaded_by,
                                                    file_name=transfer_file.file_name,
                                                    file_type=transfer_file.file_type,
                                                    google_docs=transfer_file.google_docs,
                                                    amara=transfer_file.amara)
    clone_file(
        "{}{}[{}]{}".format(archive_path, upload_path[sub_directory], transfer_file.version, transfer_file.file_name),
        "{}{}{}".format(UPLOAD_FOLDER, upload_path[sub_directory], transfer_file.file_name)
    )
    return redirect(url_for('archive_files'))


# @app.route('/toarchive/<path:directory>/<filename>/<filetype>', methods=('GET', 'POST'))
# @role_required(["admin", "superadmin"])
# def to_archive(directory, filename, filetype):
#
#     # steps for moving a file from main stage to archive of appropriate stage
#
#     # gets sub directory from full directory path
#     # example 'C:\\Users\\murli\\PycharmProjects\\FileSorting\\static\\uploads\\stageone\\'
#     # ['C:', 'Users', 'murli', 'PycharmProjects', 'FileSorting', 'static', 'uploads', 'stageone', '']
#     # second to last = sub_directory
#     #                                                has to be like this because extra space at the end like above
#     sub_directory = directory.split('{}'.format(sep))[-1 if "/" in directory else -2]
#     # get file in main stage
#     print(directory)
#     print(sub_directory)
#     stage_file = upload_tables[sub_directory].get((upload_tables[sub_directory].file_name == filename) &
#                                                   (upload_tables[sub_directory].file_type == filetype))
#     # check if file already exists in archive
#     try:
#         uploaded_archives[sub_directory].get((uploaded_archives[sub_directory].file_name == filename) &
#                                              (uploaded_archives[sub_directory].file_type == filetype))
#     except models.DoesNotExist:
#         # if it doesn't exist in archive create an archive entry
#         version = 1
#         archive_file = uploaded_archives[sub_directory].create_archive_entry(uploaded_by=stage_file.uploaded_by_id, file_name=filename,
#                                                             version=version, file_type=filetype)
#         # actually move file from main stage directory to archive directory
#         os.rename("{}{}{}".format(UPLOAD_FOLDER, upload_path[sub_directory], filename), "{}{}[{}]{}".format(archive_path, upload_path[sub_directory],
#                                                                              version, filename))
#         send_mail('File to archive', sender_email, [receiver], "{} has moved {} to the {} archive".format(
#             g.user.username, filename, sub_directory
#         ))
#         # delete stage_file from stage table
#         download_entry = download_tables[sub_directory].get_file(g.user._get_current_object(), stage_file)
#         if download_entry:
#             download_entry.delete_instance()
#         stage_file.delete_instance()
#         download_archives[sub_directory].create_entry(g.user._get_current_object(), archive_file)
#         flash("File moved!", "success")
#         return redirect(url_for('admin_files'))
#     else:
#         try:
#             uploaded_archives[sub_directory].get((uploaded_archives[sub_directory].file_name == filename) &
#                                                  (uploaded_archives[sub_directory].file_type == filetype) &
#                                                  (uploaded_archives[sub_directory].uploaded_by == stage_file.uploaded_by))
#         except models.DoesNotExist:
#             # if it exists
#             # get number of versions
#             version = uploaded_archives[sub_directory].select().where(
#                 (uploaded_archives[sub_directory].file_name == filename) &
#                 (uploaded_archives[sub_directory].file_type == filetype)
#             ).count() + 1
#             # create archive entry with appropriate version
#             archive_file = uploaded_archives[sub_directory].create_archive_entry(uploaded_by=stage_file.uploaded_by_id, file_name=filename,
#                                                                   version=version, file_type=filetype)
#             # actually move file from main stage to archive directory
#             os.rename("{}{}{}".format(UPLOAD_FOLDER, upload_path[sub_directory], filename), "{}{}[{}]{}".format(archive_path, upload_path[sub_directory],
#                                                                                  version, filename))
#             # delete stage_file from stage table
#             send_mail('File to archive', sender_email, [receiver], "{} has moved {} to the {} archive".format(
#                 g.user.username, filename, sub_directory
#             ))
#             download_entry = download_tables[sub_directory].get_file(g.user._get_current_object(), stage_file)
#             if download_entry:
#                 download_entry.delete_instance()
#             stage_file.delete_instance()
#             download_archives[sub_directory].create_entry(g.user._get_current_object(), archive_file)
#             flash("File moved!", "success")
#             return redirect(url_for('admin_files'))
#         else:
#             flash("file moved", "success")
#             # don't forget to actually remove the file from the folder!!!!
#             os.remove("{}{}{}".format(UPLOAD_FOLDER, upload_path[sub_directory], stage_file.file_name))
#             send_mail('File to archive', sender_email, [receiver], "{} has moved {} to the {} archive".format(
#                 g.user.username, filename, sub_directory
#             ))
#             download_entries = download_tables[sub_directory].select().where(
#                 download_tables[sub_directory].file == stage_file)
#             for item in download_entries:
#                 item.delete_instance()
#             stage_file.delete_instance()
#             return redirect(url_for('admin_files'))


# add flash messages before return redirects!!!!
# @app.route('/fromarchive/<path:directory>/<filename>/<filetype>/<int:version>', methods=('GET', 'POST'))
# @role_required(["admin", "superadmin"])
# def from_archive(directory, filename, filetype, version):
#     sub_directory = directory.split('{}'.format(sep))[-1 if "/" in directory else -2]
#     new_file = uploaded_archives[sub_directory].get((uploaded_archives[sub_directory].file_name==filename)
#     & (uploaded_archives[sub_directory].file_type==filetype) &
#     (uploaded_archives[sub_directory].version==version))
#     try:
#         # checks if a version of the new_file or new_file exists in main stage
#         old_file = upload_tables[sub_directory].get((upload_tables[sub_directory].file_name==filename) &
#         (upload_tables[sub_directory].file_type==filetype))
#         worked_on = old_file.worked_on
#     except models.DoesNotExist:
#         # if no file in main stage already create entry of new_file in main stage table and copy actual file over
#         upload_tables[sub_directory].create_stage_entry(uploaded_by=new_file.uploaded_by_id,
#                                                         file_name=filename, file_type=filetype)
#         copyfile("{}{}[{}]{}".format(archive_path, upload_path[sub_directory], new_file.version, new_file.file_name),
#                  "{}{}{}".format(UPLOAD_FOLDER, upload_path[sub_directory], new_file.file_name))
#         send_mail('File to stage', sender_email, [receiver], "{} has moved {} to {}".format(
#             g.user.username, filename, sub_directory
#         ))
#         return redirect(url_for('archive_files'))
#     else:
#         # if a version of new_file is in main stage check if it's in archive also
#         try:
#             uploaded_archives[sub_directory].get((uploaded_archives[sub_directory].uploaded_by==old_file.uploaded_by) &
#                                                  (uploaded_archives[sub_directory].file_name==filename) &
#                                                  (uploaded_archives[sub_directory].file_type==filetype))
#         except models.DoesNotExist:
#             # get next version number available
#             version =  uploaded_archives[sub_directory].next_file_version(file_name=filename, file_type=filetype)
#             # create archive entry
#             uploaded_archives[sub_directory].create_archive_entry(uploaded_by=old_file.uploaded_by_id,
#                                                                   file_name=old_file.file_name,
#                                                                   version=version,
#                                                                   file_type=old_file.file_type,
#                                                                   worked_on=worked_on)
#             # actually move file from main stage to archive here
#             os.rename("{}{}{}".format(UPLOAD_FOLDER, upload_path[sub_directory], old_file.file_name),
#                       "{}{}[{}]{}".format(archive_path, upload_path[sub_directory],
#                                             version, old_file.file_name))
#             old_file.delete_instance()
#             upload_tables[sub_directory].create_stage_entry(uploaded_by=new_file.uploaded_by_id,
#                                                             file_name=filename, file_type=filetype)
#             copyfile(
#                 "{}{}[{}]{}".format(archive_path, upload_path[sub_directory], new_file.version, new_file.file_name),
#                 "{}{}{}".format(UPLOAD_FOLDER, upload_path[sub_directory], new_file.file_name))
#             send_mail('File to stage', sender_email, [receiver], "{} has moved {} to {}".format(
#                 g.user.username, filename, sub_directory
#             ))
#             return redirect(url_for('archive_files'))
#         else:
#             # if old_file is in archive already delete instance of old_file in main stage table
#             os.remove("{}{}{}".format(UPLOAD_FOLDER, upload_path[sub_directory], old_file.file_name))
#             old_file.delete_instance()
#             # and save new_file in main stage and copy actual file from archive folder to main stage folder
#             upload_tables[sub_directory].create_stage_entry(uploaded_by=new_file.uploaded_by_id,
#                                                             file_name=filename, file_type=filetype)
#             copyfile(
#                 "{}{}[{}]{}".format(archive_path, upload_path[sub_directory], new_file.version, new_file.file_name),
#                 "{}{}{}".format(UPLOAD_FOLDER, upload_path[sub_directory], new_file.file_name))
#             send_mail('File to stage', sender_email, [receiver], "{} has moved {} to {}".format(
#                 g.user.username, filename, sub_directory
#             ))
#             return redirect(url_for('archive_files'))

if __name__ == '__main__':
    app.run(debug=True)


