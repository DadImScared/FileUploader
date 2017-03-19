
import os
from unittest import TestCase, main
import FileSorting
import inspect
import sys
from abc import ABCMeta
from playhouse.test_utils import test_database
from peewee import *
from models import *
from functools import wraps
from flask import render_template

dir_path = os.path.dirname(os.path.realpath(__file__))

new_database = SqliteDatabase(':memory:')



roles = [("stageone", "stage one"), ("stagetwo", "stage two"),
         ("stagethree", "stage three"), ("stagefour", "stage four"),
         ("admin", "admin"), ("superadmin", "super admin")]


class TestCaseWithPeewee(TestCase):

    __metaclass__ = ABCMeta

    def run(self, result=None):
        model_classes = [m[1] for m in inspect.getmembers(sys.modules['models'], inspect.isclass) if
                         issubclass(m[1], Model) and m[1] != Model]
        with test_database(new_database, model_classes):
            super(TestCaseWithPeewee, self).run(result)


class TestUserTable(TestCaseWithPeewee):

    def setUp(self):
        self.create_data()

    def create_data(self):
        for role in roles:
            Role.create(name=role[0], description=role[1])
        for i in range(10):
            User.create_user("tom{}".format(i), "tomemail{}@esfsef.com".format(i), "password")

    def test_create_user(self):
        """Test for create user method"""
        user = User.create_user("mike", "krutonslol@gmail.com", "password", "stagethree")
        self.assertEqual(user.username, "mike")

    def test_data(self):
        self.assertIsNotNone(User.get_user((2)))

    def test_create_role_and_delete_role_and_has_any_role_and_get_role(self):
        user = User.get_user(1)
        self.assertFalse(user.has_any_role())
        user.create_role("stageone")
        self.assertTrue(user.get_role())
        self.assertTrue(user.has_any_role())
        user.delete_role("stageone")
        self.assertFalse(user.get_role())
        self.assertFalse(user.has_any_role())
        user.create_role("stageone")
        self.assertTrue(user.get_role())
        user.delete_role()
        self.assertFalse(user.get_role())

    def test_has_uploaded(self):
        user = User.get_user(1)
        self.assertFalse(user.has_uploaded("stageone", "filehere", "transcript"))

    def test_get_files(self):
        user = User.get_user(1)
        self.assertEqual(type(user.get_files()), type(("tple",)))
        file = StageOneUpload.create_stage_entry(user.id, "filenamehere", "transcript")
        self.assertEqual(user.get_files()[0][0], file)

    def test_all_records(self):
        user = User.get_user(1)
        file = StageOneUpload.create_stage_entry(user.id, "filenamehere", "transcript")
        all_files = user.all_records()
        self.assertEqual(all_files['stage'][0][1][0], file)

    def test_email_token_generator_and_verify(self):
        user = User.get_user(1)
        token = user.generate_email_token()
        self.assertEqual(user, User.verify_email_token(token))
        self.assertNotEqual(user, User.verify_email_token("soerigjsoregij"))

    def test_get_users(self):
        all_users = get_users()
        self.assertEqual(all_users.count(), 10)

    def test_role_by_id(self):
        role = role_by_id("stageone")
        self.assertEqual(role, 1)
        role = role_by_id("stagethree")
        self.assertEqual(role, 3)


class TestGetStartedTable(TestCaseWithPeewee):

    def test_add_file(self):
        new_file = GetStarted.add_file("filenamehere", "filelink here", "Filetype here")
        self.assertEqual(new_file.file_name, "filenamehere")


class TestFlaskApp(TestCaseWithPeewee):

    def setUp(self):
        FileSorting.app.config['TESTING'] = True
        self.app = FileSorting.app.test_client()


    def test_db(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)


# Database tests for functions. (things not in a class)
class TestToArchive(TestCaseWithPeewee):

    def setUp(self):
        self.create_data()

    def create_data(self):
        user = User.create_user('tom', 'tom@gmail.com', 'password')
        file = StageOneUpload.create_stage_entry(user, 'filenamehere', 'transcript')
        for _ in range(5):
            StageOneDownload.create_entry(user, file)

    def test_file_to_archive(self):
        file = StageOneUpload.get_file("filenamehere")
        self.assertTrue(StageOneUpload.select().count())
        self.assertTrue(StageOneDownload.select().count())
        file_to_archive("stageone", file)
        self.assertFalse(StageOneUpload.select().count())
        self.assertFalse(StageOneDownload.select().count())
        archive_file = StageOneArchive.get_archive_file("filenamehere")
        self.assertEquals(1, archive_file.version)
        self.assertEquals(archive_file.file_name, "filenamehere")
        self.assertEquals(5, StageOneArchiveDownload.select().count())



if __name__ == '__main__':
    main()