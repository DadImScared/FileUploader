
import models
from filecompare import add_files
import json
import os

dir_path = os.path.dirname(os.path.realpath(__file__))
with open('{0}{1}local{1}auth.json'.format(dir_path, os.path.sep)) as data_file:
    data = json.load(data_file)
    name = data['adminName']
    email = data['adminEmail']
    password = data['adminPassword']

roles = [("stageone", "stage one"), ("stagetwo", "stage two"),
         ("stagethree", "stage three"), ("stagefour", "stage four"),
         ("admin", "admin"), ("superadmin", "super admin")]
directories = [
        ("stageone", "stage one"), ("stagetwo", "stage two"),
        ("stagethree", "stage three"), ("stagefour", "stage four")
]
models.initialize()

stages = [models.StageOneUpload, models.StageTwoUpload,
        models.StageThreeUpload, models.StageFourUpload,
        models.StageOneDownload, models.StageTwoDownload,
        models.StageThreeDownload, models.StageFourDownload,
        models.StageOneArchive, models.StageTwoArchive,
        models.StageThreeArchive, models.StageFourArchive,
        models.StageOneArchiveDownload, models.StageTwoArchiveDownload,
        models.StageThreeArchiveDownload, models.StageFourArchiveDownload]

for stage in stages:
    stage.drop_table()

models.initialize()

# for role in roles:
#     models.Role.create(name=role[0], description=role[1])

# models.User.create_user(name, email, password, ['superadmin'], True, True)

# add_files(file="mp3list.html")
# add_files(url='http://purebhakti.tv/movies.htm')

os.mkdir("{0}{1}static{1}uploads".format(dir_path, os.path.sep))
os.mkdir("{0}{1}static{1}uploads{1}archive".format(dir_path, os.path.sep))

for x in directories:
    os.mkdir("{0}{1}static{1}uploads{1}{2}".format(dir_path, os.path.sep, x[0]))
    os.mkdir("{0}{1}static{1}uploads{1}archive{1}{2}".format(dir_path, os.path.sep, x[0]))
