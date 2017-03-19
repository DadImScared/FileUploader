

from flask_testing import TestCase
import FileSorting
import inspect
import sys
from abc import ABCMeta
from playhouse.test_utils import test_database
from peewee import *
from models import *
from flask import url_for
from functools import wraps
from flask_login import current_user
from io import BytesIO
from filetools import (UPLOAD_FOLDER, archive_path,
                       upload_path, remove_file, add_file, move_file, make_test_directories,reset_test_directories)
import os

import unittest
# import flask_testing

new_database = SqliteDatabase(':memory:')

roles = [("stageone", "stage one"), ("stagetwo", "stage two"),
         ("stagethree", "stage three"), ("stagefour", "stage four"),
         ("admin", "admin"), ("superadmin", "super admin")]


def fix_format(path):
    if sys.platform == 'linux' or sys.platform == 'linux2':
        return (path).strip('/')
    else:
        return path


class TestCaseWithPeewee(TestCase):

    __metaclass__ = ABCMeta

    def run(self, result=None):
        model_classes = [m[1] for m in inspect.getmembers(sys.modules['models'], inspect.isclass) if
                         issubclass(m[1], Model) and m[1] != Model]
        with test_database(new_database, model_classes):
            super(TestCaseWithPeewee, self).run(result)


def client_context(f):
    def wrapper(*args, **kwargs):
        with args[0].client:
            return f(*args, **kwargs)
    return wrapper


class BaseTestCase(TestCaseWithPeewee):

    def create_app(self):
        FileSorting.app.config['WTF_CSRF_ENABLED'] = False
        FileSorting.app.config['MAIL_SUPPRESS_SEND'] = True
        FileSorting.UPLOAD_FOLDER = "{0}{1}static{1}testing{1}uploads{1}".format(FileSorting.dir_path, os.path.sep)
        FileSorting.archive_path = archive_path
        return FileSorting.app

    def setUp(self):
        for role in roles:
            Role.create(name=role[0], description=role[1])
        self.user = User.create_user("tom", "tom@gmail.com", "password", "stageone", True, True)
        self.second_user = User.create_user("mary", "mary@gmail.com", "password", "stageone")
        self.third_user_admin = User.create_user("jerry", "jerry@gmail.com", "password", "admin", True, True)
        # reset_test_directories()
        # make_test_directories(UPLOAD_FOLDER)
        make_test_directories(UPLOAD_FOLDER)
        with self.client:
            pass

    def tearDown(self):
        reset_test_directories()

    def test_send_mail(self):
        msg = FileSorting.Message('subject', sender="krutonslol", recipients=["crutonslol@gmail.com"],
                                  body="text body here")
        with self.app.app_context():
            with FileSorting.mail.record_messages() as outbox:
                FileSorting.mail.send(msg)
                self.assertIsNotNone(outbox)


    def test_home(self):
        response = self.client.get('/')
        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed('index.html')

    @client_context
    def test_users_can_register(self):
        info = {"username": "jeff", "email": "jeff@gmail.com",
                "password": "password", "password2": "password"}
        response = self.client.post(url_for('register'), data=info,
                                    content_type='multipart/form-data')
        self.assertMessageFlashed(
            "Thank you for registering an admin will need to confirm, in the mean time please confirm your email",
            "success")
        self.assertRedirects(response, url_for('index'))

    @client_context
    def test_users_can_confirm_email(self):
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        token = current_user.generate_email_token().decode('ascii')
        user = User.verify_email_token(token)
        self.assertTrue(user)
        response = self.client.get('/confirm/{}'.format(token))
        self.assertRedirects(response, url_for('index'))

    @client_context
    def test_users_can_login(self):
        response = self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        self.assertEqual(self.user.username, current_user.username)
        self.assertRedirects(response, url_for('index'))

    @client_context
    def test_send_confirm_email(self):
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        response = self.client.get(url_for('send_confirm_email'))
        self.assertMessageFlashed("Email sent", "success")
        self.assertRedirects(response, url_for('index'))

    @client_context
    def test_users_can_reset_password(self):
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        info = {"email": "tom@gmail.com"}
        response = self.client.post('/reset', data=json.dumps(info),
                                    content_type='application/json;charset=UTF-8')
        self.assertEquals(response.json['message'], 'success')
        self.assert200(response)
        token = current_user.generate_email_token().decode('ascii')
        response = self.client.get("/reset/{}".format(token))
        self.assertTemplateUsed('change_pass.html')

    def test_users_can_update_password(self):
        with self.client:
            response = self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
            update_response = self.client.post(url_for('edit_password'),
                                               data={
                                                   'confirm_password': 'password',
                                                   'new_password': 'taco123',
                                                   'confirm_new_password': 'taco123'
                                               })
            self.assert_message_flashed("Password updated", "success")
            self.assertRedirects(update_response, url_for('edit_user', _anchor='profile'))
            self.client.get(url_for('logout'))
            self.assert_message_flashed("You've been logged out!", "success")
            response = self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
            self.assertMessageFlashed("Your email or password doesn't match!", "danger")
            response = self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'taco123'})
            self.assertMessageFlashed("You've been logged in", "success")
            self.assertRedirects(response, url_for('index'))


    @client_context
    def test_files_route(self):
        login = self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        files = self.client.get(url_for('files'))
        self.assertEqual(type(self.get_context_variable('stage_one')),
                         type(self.get_context_variable('stage_two')))
        self.assertTemplateUsed('files.html')

    @client_context
    def test_get_started_route(self):
        login = self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        get_started = self.client.get(url_for('get_started_files'))
        self.assertEqual(type(self.get_context_variable('audio')), type(User.select()))
        self.assertEqual(type(self.get_context_variable('all_files')), type([]))
        self.assertTemplateUsed('get_started.html')

    def test_users_update_info(self):
        pass

    @client_context
    def test_user_upload(self):
        info = {'type_choice': 'transcript', 'directory_choices': 1,
                'upload': (BytesIO(b'adawfaf'), 'work.txt')}
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        response = self.client.post(url_for('index'), data=info, content_type='multipart/form-data')
        self.assertMessageFlashed("File uploaded", "success")
        self.assertRedirects(response, url_for('index'))
        # self.assertMessageFlashed("File extension doesn't match file type", "danger")

    @client_context
    def test_users_can_download(self):
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        fileName = "adawfaf"
        info = {'type_choice': 'transcript', 'directory_choices': 1,
                'upload': (BytesIO(b'adawfaf'), 'work.txt')}
        response = self.client.post(url_for('index'), data=info, content_type='multipart/form-data')
        # download_response = self.client.get('/uploads/{}/{}'.format((UPLOAD_FOLDER+upload_path["stageone"]), info['upload'][1]))
        download_response = self.client.get(url_for('downloads', directory=(
            UPLOAD_FOLDER+upload_path["stageone"]).strip('/') if sys.platform == 'linux' else \
            UPLOAD_FOLDER+upload_path["stageone"], filename="work.txt"))
        print(download_response.data)
        self.assertEquals(fileName.encode('UTF-8'), download_response.data)

    @client_context
    def test_users_profile_and_all_users(self):
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        response = self.client.get('/admin/users/120')
        self.assert404(response)
        self.client.get('/admin/users/1')
        self.assertTemplateUsed('admin/user.html')
        self.client.get(url_for('users'))
        self.assertTemplateUsed('admin/users.html')

    @client_context
    def test_get_started(self):
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        item_info = {"fileName": "file1here", "fileLink": "filelinkhere", "fileType": "Video"}
        GetStarted.add_file(item_info["fileName"], item_info["fileLink"], item_info["fileType"])
        GetStarted.add_file("file2here", "file2linkhere", "Video")
        response = self.client.post(url_for('get_started'), data=json.dumps(item_info),
                                    content_type='application/json;charset=UTF-8')
        self.assert200(response)

    @client_context
    def test_admin_can_register_users(self):
        user_info = {"username": "jeff", "email": "jeff@gmail.com", "password": "password",
                     "password2": "password", "roles": "stageone"}
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        failed_response = self.client.get(url_for('register_users'))
        self.assertRedirects(failed_response, url_for('index'))
        current_user.delete_role()
        current_user.create_role("admin")
        response = self.client.get(url_for('register_users'))
        self.assertTemplateUsed('admin/register.html')
        new_user = self.client.post(url_for('register_users'), data=user_info)
        self.assertMessageFlashed("User registered", "success")
        self.assertRedirects(new_user, url_for('register_users'))

    @client_context
    def test_admin_can_toggle_admin_confirmed_on_user(self):
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        current_user.delete_role()
        current_user.create_role("admin")
        info = {'name': "tom"}
        response = self.client.post(url_for('toggle_admin_confirmed'), data=json.dumps(info),
                                    content_type='application/json;charset=UTF-8')
        self.assert200(response)
        self.assertEquals(current_user.username, response.json)

    @client_context
    def test_admin_togglefile(self):
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        current_user.delete_role()
        current_user.create_role("admin")
        file_info = {"name": "file1name", "fileType": "file1type", "directory": "stageone"}
        StageOneUpload.create_stage_entry(current_user.id, "file1name", "file1type", "stageone")
        response = self.client.post(url_for('toggle_file'), data=json.dumps(file_info),
                                    content_type='application/json;charset=UTF-8')
        self.assertEquals(response.json, "file1name")

    @client_context
    def test_confirm_and_assign(self):
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        current_user.delete_role()
        current_user.create_role("admin")
        second_user = User.get_user(2)
        second_user.delete_role()
        self.assertFalse(second_user.get_role())
        self.assertFalse(User.get_user(2).admin_confirmed)
        assigned_user = {"name": "mary", "role": "stageone"}
        response = self.client.post(url_for('confirm_assign'), data=json.dumps(assigned_user),
                                    content_type='application/json;charset=UTF-8')
        self.assert200(response)
        self.assertTrue(User.get_user(2).get_role())
        self.assertTrue(User.get_user(2).admin_confirmed)

    @client_context
    def test_assign_role(self):
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        current_user.delete_role()
        current_user.create_role("admin")
        self.assertEquals(User.get_user(2).get_role().role.name, "stageone")
        info = {"name": "mary", "role": "admin"}
        response = self.client.post(url_for('assign_role'), data=json.dumps(info),
                                    content_type='application/json;charset=UTF-8')
        self.assertEquals(User.get_user(2).get_role().role.name, "admin")
        self.assert200(response)

    @client_context
    def test_delete_role(self):
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        current_user.delete_role()
        current_user.create_role("admin")
        info = {"name": "mary"}
        self.assertTrue(User.get_user(2).get_role())
        response = self.client.post(url_for('delete_role'), data=json.dumps(info),
                                    content_type='application/json;charset=UTF-8')
        self.assertFalse(User.get_user(2).get_role())
        self.assert200(response)

    @client_context
    def test_admin_files_view(self):
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        current_user.delete_role()
        current_user.create_role("admin")
        response = self.client.get(url_for('admin_files'))
        self.assertEquals(self.get_context_variable("stage_one"), User.select())
        self.assert200(response)
        self.assertTemplateUsed('admin/adminfiles.html')

    @client_context
    def test_admin_download_log_view(self):
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        current_user.delete_role()
        current_user.create_role("admin")
        response = self.client.get(url_for('download_log'))
        self.assert200(response)
        self.assertEquals(self.get_context_variable("get_started"), User.select())
        self.assertTemplateUsed('admin/downloads.html')

    @client_context
    def test_to_archive(self):
        info = {'type_choice': 'transcript', 'directory_choices': 1,
                'upload': (BytesIO(b'adawfaf'), 'filenamehere.txt')}
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        current_user.delete_role()
        current_user.create_role("admin")
        self.client.post(url_for('index'), data=info, content_type='multipart/form-data')
        for num in range(1, 4):
            StageOneDownload.create_entry(User.get_user(num), StageOneUpload.get_file('filenamehere.txt', 'transcript'))
        self.client.get(url_for('to_archive', directory=fix_format(UPLOAD_FOLDER+upload_path["stageone"]),
                                filename="filenamehere.txt", filetype="transcript"))
        self.assertTrue(StageOneArchive.select().count())
        self.assertEquals(StageOneArchiveDownload.select().count(), 3)
        self.assertEquals(User.get_user(1), StageOneArchiveDownload.select().get().downloaded_by)
        self.assertTrue(os.path.isfile("{}{}[{}]{}".format(archive_path, upload_path['stageone'],
                                                 1, "filenamehere.txt")))

    @client_context
    def test_breaking_to_archive(self):
        """Test to break to_archive()"""
        info = {'type_choice': 'transcript', 'directory_choices': 1,
                'upload': (BytesIO(b'adawfaf'), 'filenamehere.txt')}
        info_two = {'type_choice': 'transcript', 'directory_choices': 1,
                'upload': (BytesIO(b'adawfaf'), 'filenamehere.txt')}
        self.client.post(url_for('login'), data={'email': 'tom@gmail.com', 'password': 'password'})
        self.client.post(url_for('index'), data=info_two, content_type='multipart/form-data')
        self.client.get(url_for('logout'))
        self.client.post(url_for('login'), data={'email': 'jerry@gmail.com', 'password': 'password'})
        self.client.post(url_for('index'), data=info, content_type='multipart/form-data')
        self.client.get(url_for('to_archive', directory=fix_format(UPLOAD_FOLDER + upload_path["stageone"]),
                                filename="filenamehere.txt", filetype="transcript"))
        self.assertEquals(2, StageOneArchive.select().count())
        self.assertFalse(os.path.isfile("{}{}{}".format(UPLOAD_FOLDER, upload_path['stageone'], "filenamehere.txt")))
        self.assertTrue(os.path.isfile("{}{}[{}]{}".format(archive_path, upload_path['stageone'],
                                                           1, "filenamehere.txt")))
        self.assertTrue(os.path.isfile("{}{}[{}]{}".format(archive_path, upload_path['stageone'],
                                                           2, "filenamehere.txt")))

    @client_context
    def test_from_archive(self):
        user = User.get_user(1)
        add_file(archive_path, "stageone", "filenamehere.txt", 1)
        uploaded_archives["stageone"].create_archive_entry(uploaded_by=user,
                                                           file_name="filenamehere.txt",
                                                           file_type="transcript",
                                                           version=1)
        self.client.post(url_for('login'), data={'email': 'jerry@gmail.com', 'password': 'password'})
        self.assertFalse(StageOneUpload.select().count())
        self.client.get(url_for('from_archive', directory=fix_format(archive_path+upload_path["stageone"]),
                                filename="filenamehere.txt", filetype="transcript",
                                version=1))
        self.assertTrue(StageOneUpload.select().count())

    @client_context
    def test_breaking_from_archive(self):
        user = User.get_user(1)
        second_user = User.get_user(2)
        add_file(archive_path, "stageone", "filenamehere.txt", 1)
        uploaded_archives["stageone"].create_archive_entry(uploaded_by=user,
                                                           file_name="filenamehere.txt",
                                                           file_type="transcript",
                                                           version=1)
        add_file(archive_path, "stageone", "filenamehere.txt", 2)
        uploaded_archives["stageone"].create_archive_entry(uploaded_by=second_user,
                                                           file_name="filenamehere.txt",
                                                           file_type="transcript",
                                                           version=2)
        add_file(UPLOAD_FOLDER, "stageone", "filenamehere.txt")
        upload_tables["stageone"].create_stage_entry(uploaded_by=second_user, file_name="filenamehere.txt",
                                                     file_type="transcript")
        self.assertTrue(os.path.isfile(UPLOAD_FOLDER+upload_path["stageone"]+"filenamehere.txt"))
        self.assertEquals("mary", StageOneUpload.get_file("filenamehere.txt", "transcript").uploaded_by.username)
        self.client.post(url_for('login'), data={'email': 'jerry@gmail.com', 'password': 'password'})
        self.client.get(url_for('from_archive', directory=fix_format(archive_path + upload_path["stageone"]),
                                filename="filenamehere.txt", filetype="transcript",
                                version=1))
        self.assertEquals(StageOneArchive.select().count(), 2)
        self.assertEquals("tom", StageOneUpload.get_file("filenamehere.txt", "transcript").uploaded_by.username)


if __name__ == '__main__':
    unittest.main()
