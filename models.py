
import os
import datetime
import json
from flask_bcrypt import generate_password_hash
from flask_login import UserMixin
from peewee import *
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from random import sample
from collections import OrderedDict

dir_path = os.path.dirname(os.path.realpath(__file__))

# DATABASE = SqliteDatabase('C:\\Users\\murli\\PycharmProjects\\FileSorting\\people.db')
DATABASE = SqliteDatabase("{}{}people.db".format(dir_path, os.path.sep))

with open('{0}{1}local{1}auth.json'.format(dir_path, os.path.sep)) as data_file:
    data = json.load(data_file)
    key = data['key']


class User(UserMixin, Model):
    username = CharField(unique=True)
    email = CharField(unique=True)
    password = CharField(max_length=100)
    joined_at = DateTimeField(default=datetime.datetime.now)
    admin_confirmed = BooleanField(default=False)
    email_confirmed = BooleanField(default=False)

    class Meta:
        database = DATABASE
        order_by = ('-joined_at',)

    @classmethod
    def create_user(cls, username, email, password, roles=None, admin_confirmed=False, email_confirmed=False):
        try:
            cls.create(
                username=username,
                email=email,
                password=generate_password_hash(password),
                admin_confirmed=admin_confirmed,
                email_confirmed=email_confirmed
            )
        except IntegrityError:
            raise ValueError("User already exists")
        else:
            user = cls.get(cls.username == username)
            if roles:
                user.create_role(roles)
            return user

    @classmethod
    def get_user(cls, id=None, username=None, email=None):
        if id:
            try:
                user = cls.get(cls.id == id)
            except DoesNotExist:
                return None
            else:
                return user
        else:
            try:
                user = cls.get(cls.username == username if username else cls.email == email)
            except DoesNotExist:
                return None
            else:
                return user

    def get_role(self):
        try:
            role = UserRole.get(UserRole.user == self)
        except DoesNotExist:
            return None
        else:
            return role

    def has_role(self, role):
        try:
            return UserRole.get((UserRole.user == self.id) & (UserRole.role == role_by_id(role)))
        except DoesNotExist:
            return False

    def has_any_role(self):
        return User.select().join(
            UserRole,
            on=UserRole.user
        ).where(
            User.id == self.id
        )

    def has_uploaded(self, stage, filename, filetype):
        print("{} {} {} {}".format(self.username, stage,filename,filetype))
        try:
            file = upload_tables[stage].get(
                (upload_tables[stage].file_name==filename) &
                (upload_tables[stage].file_type==filetype) &
                (upload_tables[stage].uploaded_by==self.id)
            )
        except DoesNotExist:
            try:
                file = uploaded_archives[stage].get(
                    (uploaded_archives[stage].file_name == filename) &
                    (uploaded_archives[stage].file_type == filetype) &
                    (uploaded_archives[stage].uploaded_by == self.id)
                )
            except DoesNotExist:
                return False
            else:
                return file
        else:
            return file

    def get_files(self):
        last = None
        stage_one_files = []
        stage_two_files = []
        stage_three_files = []
        stage_four_files = []

        all_files = User.select(User, StageOneUpload, StageTwoUpload, StageThreeUpload, StageFourUpload).join(
            StageOneUpload,
            JOIN.LEFT_OUTER,
            on=(StageOneUpload.uploaded_by).alias("stageone")
        ).switch(User).join(
            StageTwoUpload,
            JOIN.LEFT_OUTER,
            on=(StageTwoUpload.uploaded_by).alias("stagetwo")
        ).switch(User).join(
            StageThreeUpload,
            JOIN.LEFT_OUTER,
            on=(StageThreeUpload.uploaded_by).alias("stagethree")
        ).switch(User).join(
            StageFourUpload,
            JOIN.LEFT_OUTER,
            on=(StageFourUpload.uploaded_by).alias("stagefour")
        ).where(User.id == self.id)


        for user in all_files:
            file1 = user.stageone
            file2 = user.stagetwo
            file3 = user.stagethree
            file4 = user.stagefour

            if file1 not in stage_one_files and file1.file_name:
                stage_one_files.append(file1)
                print(file1.file_name)
            if file2 not in stage_two_files and file2.file_name:
                stage_two_files.append(file2)
            if file3 not in stage_three_files and file3.file_name:
                stage_three_files.append(file3)
            if file4 not in stage_four_files and file4.file_name:
                stage_four_files.append(file4)
        return stage_one_files, stage_two_files, stage_three_files, stage_four_files

    def get_downloads(self):
        last = None
        stage_one_files = []
        stage_two_files = []
        stage_three_files = []
        stage_four_files = []

        all_files = User.select(User, StageOneDownload, StageTwoDownload, StageThreeDownload, StageFourDownload).join(
            StageOneDownload,
            JOIN.LEFT_OUTER,
            on=(StageOneDownload.downloaded_by).alias("stageone")
        ).switch(User).join(
            StageTwoDownload,
            JOIN.LEFT_OUTER,
            on=(StageTwoDownload.downloaded_by).alias("stagetwo")
        ).switch(User).join(
            StageThreeDownload,
            JOIN.LEFT_OUTER,
            on=(StageThreeDownload.downloaded_by).alias("stagethree")
        ).switch(User).join(
            StageFourDownload,
            JOIN.LEFT_OUTER,
            on=(StageFourDownload.downloaded_by).alias("stagefour")
        ).where(User.id == self.id)

        for user in all_files:
            file1 = user.stageone
            file2 = user.stagetwo
            file3 = user.stagethree
            file4 = user.stagefour

            if file1 not in stage_one_files:
                try:
                    name = file1.file.file_name
                except DoesNotExist:
                    pass
                else:
                    stage_one_files.append(file1)
            if file2 not in stage_two_files:
                try:
                    name = file2.file.file_name
                except DoesNotExist:
                    pass
                else:
                    stage_two_files.append(file2)
            if file3 not in stage_three_files:
                try:
                    name = file3.file.file_name
                except DoesNotExist:
                    pass
                else:
                    stage_three_files.append(file3)
            if file4 not in stage_four_files:
                try:
                    name = file4.file.file_name
                except DoesNotExist:
                    pass
                else:
                    stage_four_files.append(file4)
        return stage_one_files, stage_two_files, stage_three_files, stage_four_files

    def get_archive_files(self):
        last = None
        stage_one_files = []
        stage_two_files = []
        stage_three_files = []
        stage_four_files = []

        all_files = User.select(User, StageOneArchive, StageTwoArchive, StageThreeArchive, StageFourArchive).join(
            StageOneArchive,
            JOIN.LEFT_OUTER,
            on=(StageOneArchive.uploaded_by).alias("stageone")
        ).switch(User).join(
            StageTwoArchive,
            JOIN.LEFT_OUTER,
            on=(StageTwoArchive.uploaded_by).alias("stagetwo")
        ).switch(User).join(
            StageThreeArchive,
            JOIN.LEFT_OUTER,
            on=(StageThreeArchive.uploaded_by).alias("stagethree")
        ).switch(User).join(
            StageFourArchive,
            JOIN.LEFT_OUTER,
            on=(StageFourArchive.uploaded_by).alias("stagefour")
        ).where(User.id == self.id)

        for user in all_files:
            file1 = user.stageone
            file2 = user.stagetwo
            file3 = user.stagethree
            file4 = user.stagefour

            if file1 not in stage_one_files and file1.file_name:
                stage_one_files.append(file1)
                print(file1.file_name)
            if file2 not in stage_two_files and file2.file_name:
                stage_two_files.append(file2)
            if file3 not in stage_three_files and file3.file_name:
                stage_three_files.append(file3)
            if file4 not in stage_four_files and file4.file_name:
                stage_four_files.append(file4)
        return stage_one_files, stage_two_files, stage_three_files, stage_four_files

    def get_archive_downloads(self):
        last = None
        stage_one_files = []
        stage_two_files = []
        stage_three_files = []
        stage_four_files = []

        all_files = User.select(User, StageOneArchiveDownload, StageTwoArchiveDownload,StageThreeArchiveDownload, StageFourArchiveDownload).join(
            StageOneArchiveDownload,
            JOIN.LEFT_OUTER,
            on=(StageOneArchiveDownload.downloaded_by).alias("stageone")
        ).switch(User).join(
            StageTwoArchiveDownload,
            JOIN.LEFT_OUTER,
            on=(StageTwoArchiveDownload.downloaded_by).alias("stagetwo")
        ).switch(User).join(
            StageThreeArchiveDownload,
            JOIN.LEFT_OUTER,
            on=(StageThreeArchiveDownload.downloaded_by).alias("stagethree")
        ).switch(User).join(
            StageFourArchiveDownload,
            JOIN.LEFT_OUTER,
            on=(StageFourArchiveDownload.downloaded_by).alias("stagefour")
        ).where(User.id == self.id)

        for user in all_files:
            file1 = user.stageone
            file2 = user.stagetwo
            file3 = user.stagethree
            file4 = user.stagefour

            if file1 not in stage_one_files:
                try:
                    name = file1.file
                except DoesNotExist:
                    pass
                else:
                    stage_one_files.append(file1)
            if file2 not in stage_two_files:
                try:
                    name = file2.file
                except DoesNotExist:
                    pass
                else:
                    stage_two_files.append(file2)
            if file3 not in stage_three_files:
                try:
                    name = file3.file
                except DoesNotExist:
                    pass
                else:
                    stage_three_files.append(file3)
            if file4 not in stage_four_files:
                try:
                    name = file4.file
                except DoesNotExist:
                    pass
                else:
                    stage_four_files.append(file4)
        return stage_one_files, stage_two_files, stage_three_files, stage_four_files

    def every_file(self):
        all_files = {}
        stage_files = self.get_files()
        stage_downloads = self.get_downloads()
        archive_files = self.get_archive_files()
        archive_downloads = self.get_archive_downloads()
        all_files["stage"] = stage_files
        all_files['stageDownload'] = stage_downloads
        all_files['archive'] = archive_files
        all_files['archiveDownload'] = archive_downloads
        return all_files

    def big_query(self):
        return User.select(User, StageOneUpload, StageTwoUpload, StageThreeUpload, StageFourUpload,
                                StageOneDownload, StageTwoDownload, StageThreeDownload, StageFourDownload,
                                StageOneArchive, StageTwoArchive, StageThreeArchive, StageFourArchive,
                                StageOneArchiveDownload, StageTwoArchiveDownload,
                                StageThreeArchiveDownload, StageFourArchiveDownload) \
            .join(
            StageOneUpload,
            JOIN.LEFT_OUTER,
            on=(StageOneUpload.uploaded_by).alias("stageone")
        ).switch(User).join(
            StageTwoUpload,
            JOIN.LEFT_OUTER,
            on=(StageTwoUpload.uploaded_by).alias("stagetwo")
        ).switch(User).join(
            StageThreeUpload,
            JOIN.LEFT_OUTER,
            on=(StageThreeUpload.uploaded_by).alias("stagethree")
        ).switch(User).join(
            StageFourUpload,
            JOIN.LEFT_OUTER,
            on=(StageFourUpload.uploaded_by).alias("stagefour")
        ).switch(User).join(
            StageOneDownload,
            JOIN.LEFT_OUTER,
            on=(StageOneDownload.downloaded_by).alias('stageonedownloads')
        ).switch(User).join(
            StageTwoDownload,
            JOIN.LEFT_OUTER,
            on=(StageTwoDownload.downloaded_by).alias('stagetwodownloads')
        ).switch(User).join(
            StageThreeDownload,
            JOIN.LEFT_OUTER,
            on=(StageThreeDownload.downloaded_by).alias('stagethreedownloads')
        ).switch(User).join(
            StageFourDownload,
            JOIN.LEFT_OUTER,
            on=(StageFourDownload.downloaded_by).alias('stagefourdownloads')
        ).switch(User).join(
            StageOneArchive,
            JOIN.LEFT_OUTER,
            on=(StageOneArchive.uploaded_by).alias("stageonearchive")
        ).switch(User).join(
            StageTwoArchive,
            JOIN.LEFT_OUTER,
            on=(StageTwoArchive.uploaded_by).alias("stagetwoarchive")
        ).switch(User).join(
            StageThreeArchive,
            JOIN.LEFT_OUTER,
            on=(StageThreeArchive.uploaded_by).alias("stagethreearchive")
        ).switch(User).join(
            StageFourArchive,
            JOIN.LEFT_OUTER,
            on=(StageFourArchive.uploaded_by).alias("stagefourarchive")
        ).switch(User).join(
            StageOneArchiveDownload,
            JOIN.LEFT_OUTER,
            on=(StageOneArchiveDownload.downloaded_by).alias("stageonearchivedownload")
        ).switch(User).join(
            StageTwoArchiveDownload,
            JOIN.LEFT_OUTER,
            on=(StageTwoArchiveDownload.downloaded_by).alias("stagetwoarchivedownload")
        ).switch(User).join(
            StageThreeArchiveDownload,
            JOIN.LEFT_OUTER,
            on=(StageThreeArchiveDownload.downloaded_by).alias("stagethreearchivedownload")
        ).switch(User).join(
            StageFourArchiveDownload,
            JOIN.LEFT_OUTER,
            on=(StageFourArchiveDownload.downloaded_by).alias("stagefourarchivedownload")
        ).switch(User).where(User.id == self.id)

    def all_records(self):
        last = None
        stage_one_files = []
        stage_two_files = []
        stage_three_files = []
        stage_four_files = []
        stage_one_downloads = []
        stage_two_downloads = []
        stage_three_downloads = []
        stage_four_downloads = []
        stage_one_archive = []
        stage_two_archive = []
        stage_three_archive = []
        stage_four_archive = []
        stage_one_archive_downloads = []
        stage_two_archive_downloads = []
        stage_three_archive_downloads = []
        stage_four_archive_downloads = []

        all_files = self.big_query()

        for user in all_files:
            file1 = user.stageone
            file2 = user.stagetwo
            file3 = user.stagethree
            file4 = user.stagefour
            file1_download = user.stageonedownloads
            file2_download = user.stagetwodownloads
            file3_download = user.stagethreedownloads
            file4_download = user.stagefourdownloads
            archive_file1 = user.stageonearchive
            archive_file2 = user.stagetwoarchive
            archive_file3 = user.stagethreearchive
            archive_file4 = user.stagefourarchive
            archive_download1 = user.stageonearchivedownload
            archive_download2 = user.stagetwoarchivedownload
            archive_download3 = user.stagethreearchivedownload
            archive_download4 = user.stagefourarchivedownload

            # main stage files
            if file1 not in stage_one_files and file1.file_name:
                stage_one_files.append(file1)
            if file2 not in stage_two_files and file2.file_name:
                stage_two_files.append(file2)
            if file3 not in stage_three_files and file3.file_name:
                stage_three_files.append(file3)
            if file4 not in stage_four_files and file4.file_name:
                stage_four_files.append(file4)

            # main stage downloads
            if file1_download not in stage_one_downloads:
                try:
                    name = file1_download.file.file_name
                except DoesNotExist:
                    pass
                else:
                    stage_one_downloads.append(file1_download)
            if file2_download not in stage_two_downloads:
                try:
                    name = file2_download.file.file_name
                except DoesNotExist:
                    pass
                else:
                    stage_two_downloads.append(file2_download)
            if file3_download not in stage_three_downloads:
                try:
                    name = file3_download.file.file_name
                except DoesNotExist:
                    pass
                else:
                    stage_three_downloads.append(file3_download)
            if file4_download not in stage_four_downloads:
                try:
                    name = file4_download.file.file_name
                except DoesNotExist:
                    pass
                else:
                    stage_four_downloads.append(file4_download)

            # archive files
            if archive_file1 not in stage_one_archive and archive_file1.file_name:
                stage_one_archive.append(archive_file1)
            if archive_file2 not in stage_two_archive and archive_file2.file_name:
                stage_two_archive.append(archive_file2)
            if archive_file3 not in stage_three_archive and archive_file3.file_name:
                stage_three_archive.append(archive_file3)
            if archive_file4 not in stage_four_archive and archive_file4.file_name:
                stage_four_archive.append(archive_file4)

            # archive downloads
            if archive_download1 not in stage_one_archive_downloads:
                try:
                    name = archive_download1.file.file_name
                except DoesNotExist:
                    pass
                else:
                    stage_one_archive_downloads.append(archive_download1)
            if archive_download2 not in stage_two_archive_downloads:
                try:
                    name = archive_download2.file.file_name
                except DoesNotExist:
                    pass
                else:
                    stage_two_archive_downloads.append(archive_download2)
            if archive_download3 not in stage_three_archive_downloads:
                try:
                    name = archive_download3.file.file_name
                except DoesNotExist:
                    pass
                else:
                    stage_three_archive_downloads.append(archive_download3)
            if archive_download4 not in stage_four_archive_downloads:
                try:
                    name = archive_download4.file.file_name
                except DoesNotExist:
                    pass
                else:
                    stage_four_archive_downloads.append(archive_download4)
        everything = OrderedDict()
        everything['stage'] = [("Stage One Files", stage_one_files),
                               ("Stage Two Files", stage_two_files),
                               ("Stage Three Files", stage_three_files),
                               ("Stage Four Files", stage_four_files)]
        everything['archive'] = [("Stage One Archive", stage_one_archive),
                                 ("Stage Two Archive", stage_two_archive),
                                 ("Stage Three Archive", stage_three_archive),
                                 ("Stage Four Archive", stage_four_archive)]
        everything['stageDownload'] = [("Stage One Downloads", stage_one_downloads),
                                       ("Stage Two Downloads", stage_two_downloads),
                                       ("Stage Three Downloads", stage_three_downloads),
                                       ("Stage Four Downloads", stage_four_downloads)]
        everything['archiveDownload'] = [("Stage One Archive Downloads", stage_one_archive_downloads),
                                         ("Stage Two Archive Downloads", stage_two_archive_downloads),
                                         ("Stage Three Archive Downloads", stage_three_archive_downloads),
                                         ("Stage Four Archive Downloads", stage_four_archive_downloads)]
        # everything['stage'] = [stage_one_files, stage_two_files, stage_three_files, stage_four_files]
        # everything['archive'] = [stage_one_archive, stage_two_archive, stage_three_archive, stage_four_archive]
        # everything['stageDownload'] = [stage_one_downloads, stage_two_downloads,
        #                                stage_three_downloads, stage_four_downloads]
        # everything['archiveDownload'] = [stage_one_archive_downloads, stage_two_archive_downloads,
        #                                  stage_three_archive_downloads, stage_four_archive_downloads]
        # return (stage_one_files, stage_two_files, stage_three_files, stage_four_files, stage_one_downloads,
        #         stage_two_downloads, stage_three_downloads, stage_four_downloads,
        #         stage_one_archive, stage_two_archive, stage_three_archive, stage_four_archive,
        #         stage_one_archive_downloads, stage_two_archive_downloads, stage_three_archive_downloads,
        #         stage_four_archive_downloads)
        return everything

    # FIX CREATE_ROLE BECAUSE YOU CHANGED IT FROM CREATE_ROLES MAKE IT TAKE STRING NOT LIST
    def create_role(self, roles):
        for role in roles:
            if not self.has_role(role):
                try:
                    UserRole.create(user=self.id, role=role_by_id(role))
                except IntegrityError:
                    pass

    def delete_role(self, role=None):
        if role:
            try:
                user_role = UserRole.get((UserRole.user == self) & (UserRole.role == role_by_id(role)))
            except DoesNotExist:
                return None
            else:
                user_role.delete_instance()
                return

        try:
            user_role = UserRole.get(UserRole.user == self)
        except DoesNotExist:
            return None
        else:
            user_role.delete_instance()

    def generate_email_token(self, expiration=600):
        s = Serializer(key, expires_in=expiration)
        return s.dumps({"email": self.email})

    @staticmethod
    def verify_email_token(token):
        s = Serializer(key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        user = User.get(User.email == data['email'])
        return user


def get_users():
    return User.select().order_by('-id')


def role_by_id(role):
    return Role.get(Role.name == role).id


class Role(Model):
    name = CharField(max_length=120)
    description = TextField(null=True)

    class Meta:
        database = DATABASE


class UserRole(Model):
    user = ForeignKeyField(rel_model=User, related_name="from_user", unique=True)
    role = ForeignKeyField(rel_model=Role, related_name="to_role")

    class Meta:
        database = DATABASE


class GetStarted(Model):
    file_name = CharField(unique=True)
    file_link = CharField()
    file_type = CharField()
    worked_on = BooleanField(default=False)

    @classmethod
    def get_file(cls, file_name, file_type=None):

        if file_type:
            try:
                return cls.get((cls.file_name == file_name) & (cls.file_type == file_type))
            except DoesNotExist:
                pass
        else:
            try:
                return cls.get(cls.file_name == file_name)
            except DoesNotExist:
                pass

    @classmethod
    def random_records(cls, file_type, limit):
        return cls.select().where((cls.file_type == file_type) &
                                  ~(cls.worked_on)).order_by(fn.Random()).limit(limit)

    class Meta:
        database = DATABASE


class GetStartedDownloads(Model):
    user = ForeignKeyField(rel_model=User, related_name="get_started_users")
    file = ForeignKeyField(rel_model=GetStarted, related_name='get_started_files', unique=True)
    started_at = DateTimeField(default=datetime.datetime.now)
    on_stage = BooleanField(default=False)

    class Meta:
        database = DATABASE
        order_by = ('started_at',)

    @classmethod
    def create_entry(cls, user, file, stage=False):
        try:
            return cls.create(user=user, file=file, on_stage=stage)
        except IntegrityError:
            pass

    @classmethod
    def in_get_started_downloads(cls, filename):
        try:
            return cls.get(cls.file == GetStarted.get_file(filename).id)
        except AttributeError:
            return None


# All Download tables inherit from this base model
class BaseStageDownload(Model):
    # file_name = CharField(unique=True)
    downloaded_at = DateTimeField(default=datetime.datetime.now)
    # file_type = CharField()

    class Meta:
        database = DATABASE
        order_by = ('-downloaded_at',)

    @classmethod
    def create_entry(cls, user, file):
        return cls.create(downloaded_by=user, file=file)

    @classmethod
    def get_file(cls, user, file):
        try:
            return cls.get((cls.downloaded_by==user) & (cls.file==file))
        except DoesNotExist:
            return None


# All Upload folders inherit from this base model
class BaseStageUpload(Model):
    uploaded_at = DateTimeField(default=datetime.datetime.now)
    file_name = CharField(unique=True)
    worked_on = BooleanField(default=False)
    file_type = CharField()
    google_docs = CharField(null=True)

    class Meta:
        database = DATABASE
        order_by = ('-uploaded_at',)

    @classmethod
    def create_stage_entry(cls, uploaded_by, file_name, file_type, worked_on=False):
        try:
            cls.create(
                uploaded_by=uploaded_by,
                file_name=file_name,
                file_type=file_type,
                worked_on=worked_on
            )
        except IntegrityError:
            return None
        else:
            return cls.get(cls.file_name == file_name)

    @classmethod
    def get_file(cls, file_name, file_type=None):
        if file_type:
            try:
                file = cls.get((cls.file_name == file_name) & (cls.file_type == file_type))
            except DoesNotExist:
                return None
            else:
                return file
        else:
            try:
                file = cls.get(cls.file_name == file_name)
            except DoesNotExist:
                return None
            return file

    @classmethod
    def has_google_doc(cls):
        return cls.select().where((cls.worked_on == False) & (cls.google_docs != None ))

    # @classmethod
    # def check_worked_on(cls, name_part, file_type):
    #     try:
    #         cls.get((cls.file_name.contains(name_part)) & (~(cls.file_type == file_type)))


class BaseArchiveUpload(BaseStageUpload):
    file_name = CharField(max_length=255)
    version = IntegerField()

    @classmethod
    def create_archive_entry(cls, uploaded_by, file_name, version, file_type, worked_on=False):
        return cls.create(
            uploaded_by=uploaded_by,
            file_name=file_name,
            version=version,
            file_type=file_type,
            worked_on=worked_on
        )

    @classmethod
    def next_file_version(cls, file_name, file_type):
            return cls.select().where((cls.file_name==file_name) & (cls.file_type==file_type)).count() + 1

    @classmethod
    def get_archive_file(cls, filename, version=None):
        if version:
            try:
                return cls.get((cls.file_name==filename) &  (cls.version==version))
            except DoesNotExist:
                return None
        else:
            try:
                return cls.get((cls.file_name==filename))
            except DoesNotExist:
                return None


class StageOneUpload(BaseStageUpload):
    uploaded_by = ForeignKeyField(
        rel_model=User,
        related_name="stage_one_uploads"
    )


class StageTwoUpload(BaseStageUpload):
    uploaded_by = ForeignKeyField(
        rel_model=User,
        related_name="stage_two_uploads"
    )


class StageThreeUpload(BaseStageUpload):
    uploaded_by = ForeignKeyField(
        rel_model=User,
        related_name="stage_three_uploads"
    )


class StageFourUpload(BaseStageUpload):
    uploaded_by = ForeignKeyField(
        rel_model=User,
        related_name="stage_four_uploads"
    )


class StageOneDownload(BaseStageDownload):
    downloaded_by = ForeignKeyField(
        rel_model=User,
        related_name="stage_one_downloads"
    )
    file = ForeignKeyField(
        rel_model=StageOneUpload,
        related_name="stage_one_files"
    )


class StageTwoDownload(BaseStageDownload):
    downloaded_by = ForeignKeyField(
        rel_model=User,
        related_name="stage_two_downloads"
    )
    file = ForeignKeyField(
        rel_model=StageTwoUpload,
        related_name="stage_two_files"
    )


class StageThreeDownload(BaseStageDownload):
    downloaded_by = ForeignKeyField(
        rel_model=User,
        related_name="stage_three_downloads"
    )
    file = ForeignKeyField(
        rel_model=StageThreeUpload,
        related_name="stage_three_files"
    )


class StageFourDownload(BaseStageDownload):
    downloaded_by = ForeignKeyField(
        rel_model=User,
        related_name="stage_four_downloads"
    )
    file = ForeignKeyField(
        rel_model=StageFourUpload,
        related_name="stage_four_files"
    )


class StageOneArchive(BaseArchiveUpload):
    uploaded_by = ForeignKeyField(
        rel_model=User,
        related_name='stage_one_archive'
    )


class StageTwoArchive(BaseArchiveUpload):
    uploaded_by = ForeignKeyField(
        rel_model=User,
        related_name='stage_two_archive'
    )


class StageThreeArchive(BaseArchiveUpload):
    uploaded_by = ForeignKeyField(
        rel_model=User,
        related_name='stage_three_archive'
    )


class StageFourArchive(BaseArchiveUpload):
    uploaded_by = ForeignKeyField(
        rel_model=User,
        related_name='stage_four_archive'
    )


class StageOneArchiveDownload(BaseStageDownload):
    downloaded_by = ForeignKeyField(
        rel_model=User,
        related_name="stage_one_archive_downloads"
    )
    file = ForeignKeyField(
        rel_model=StageOneArchive,
        related_name="stage_one_archive_files"
    )


class StageTwoArchiveDownload(BaseStageDownload):
    downloaded_by = ForeignKeyField(
        rel_model=User,
        related_name="stage_two_archive_downloads"
    )
    file = ForeignKeyField(
        rel_model=StageTwoArchive,
        related_name="stage_two_archive_files"
    )


class StageThreeArchiveDownload(BaseStageDownload):
    downloaded_by = ForeignKeyField(
        rel_model=User,
        related_name="stage_three_archive_downloads"
    )
    file = ForeignKeyField(
        rel_model=StageThreeArchive,
        related_name="stage_three_archive_files"
    )


class StageFourArchiveDownload(BaseStageDownload):
    downloaded_by = ForeignKeyField(
        rel_model=User,
        related_name="stage_four_archive_downloads"
    )
    file = ForeignKeyField(
        rel_model=StageFourArchive,
        related_name="stage_four_archive_files"
    )


upload_tables = {
    "stageone": StageOneUpload,
    "stagetwo": StageTwoUpload,
    "stagethree": StageThreeUpload,
    "stagefour": StageFourUpload
}


download_tables = {
    "stageone": StageOneDownload,
    "stagetwo": StageTwoDownload,
    "stagethree": StageThreeDownload,
    "stagefour": StageFourDownload
}


uploaded_archives = {
    "stageone": StageOneArchive,
    "stagetwo": StageTwoArchive,
    "stagethree": StageThreeArchive,
    "stagefour": StageFourArchive
}


download_archives = {
    "stageone": StageOneArchiveDownload,
    "stagetwo": StageTwoArchiveDownload,
    "stagethree": StageThreeArchiveDownload,
    "stagefour": StageFourArchiveDownload
}


def file_exists(stage, file_name, file_type, uploaded_by=None):
    if uploaded_by:
        try:
            file = upload_tables[stage].get((upload_tables[stage].file_name==file_name) &
                                     (upload_tables[stage].file_type==file_type) &
                                     (upload_tables[stage].uploaded_by==uploaded_by))
        except DoesNotExist:
            return None
        else:
            return file
    else:
        try:
            file = upload_tables[stage].get((upload_tables[stage].file_name==file_name) &
                                     (upload_tables[stage].file_type==file_type))
        except DoesNotExist:
            return None
        else:
            return file


def file_in_archive(stage, file_name, file_type, version=None, uploaded_by=None, order=None):
    if version:
        # look up with version
        pass
    elif uploaded_by:
        try:
            file = uploaded_archives[stage].get(
                uploaded_archives[stage].file_name==file_name,
                uploaded_archives[stage].file_type==file_type,
                uploaded_archives[stage].uploaded_by==uploaded_by
            )
        except DoesNotExist:
            return False
        else:
            return file

    else:
        files = uploaded_archives[stage].select().where((uploaded_archives[stage].file_name==file_name) &
                                                        (uploaded_archives[stage].file_type==file_type))
        return files


def opposite_file_workedon(stage, file_name, file_type):
    try:
        file = upload_tables[stage].get((upload_tables[stage].file_name.startswith(file_name.rsplit(".")[0][:9])) &
                                        (~upload_tables[stage].file_type==file_type))
    except DoesNotExist:
        return False
    else:
        return file.worked_on


def downloads():
    download_one = StageOneDownload.select()
    download_two = StageTwoDownload.select()
    download_three = StageThreeDownload.select()
    download_four = StageFourDownload.select()
    archive_one = StageOneArchiveDownload.select()
    archive_two = StageTwoArchiveDownload.select()
    archive_three = StageThreeArchiveDownload.select()
    archive_four = StageFourArchiveDownload.select()

    return [("Stage One Downloads", download_one), ("Stage Two Downloads", download_two),
            ("Stage Three Downloads", download_three), ("Stage Four Downloads", download_four),
            ("Stage One Archive Downloads", archive_one), ("Stage Two Archive Downloads", archive_two),
            ("Stage Three Archive Downloads", archive_three), ("Stage Four Archive Downloads", archive_four)]



tables = [StageOneUpload, StageTwoUpload, StageThreeUpload, StageFourUpload, StageOneDownload, StageTwoDownload,
          StageThreeDownload, StageFourDownload, GetStarted, GetStartedDownloads,
          StageOneArchive, StageTwoArchive, StageThreeArchive, StageFourArchive,
          StageOneArchiveDownload, StageTwoArchiveDownload, StageThreeArchiveDownload, StageFourArchiveDownload]

def initialize():
    DATABASE.connect()
    DATABASE.create_tables([User, Role, UserRole, *tables], safe=True)
    DATABASE.close()
