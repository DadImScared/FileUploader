
from bs4 import BeautifulSoup as bs
from urllib.request import Request, urlopen
import re
from models import GetStarted, DATABASE, IntegrityError

# url = 'http://purebhakti.tv/movies.htm'

# urlopen(req)


valid_string = r'^[0-9]{4}-?\s?[0-9]{2}-?\s?[0-9]{2}'

date_check = r'^[0-9]{2}\s?-?_?[0-9]{2}\s?-?_?[0-9]{2}[a-zA-Z\s?-?]'


# add worked on column

# for link in soup.find_all('a'):
#     try:
#         empty_list.append((link.string.lstrip()[0:8],
#                            link.string.strip().replace("\n", "").replace("\t", ""),
#                            link.get('href').strip().replace('\'', "")))
#     except AttributeError:
#         pass


def extension_check(string):
    return string.rsplit('.', 1)[1]


def normalize(string):
    return re.sub(r'[_, \s\t\n]*', "", str(re.split(valid_string, string)[1])).rsplit(".", 1)[0]
    # return type(tpl[1])


def add_files(url=None, file=None):
    complete_files = done_files()
    if url:
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        soup = bs(urlopen(req), 'html.parser')
        all_files = get_links(soup)
        fixed_dates = fix_dates(all_files)
        all_files = all_files + fixed_dates
        available_files = audio_video("Video", all_files, complete_files)
        to_database(available_files)
    if file:
        soup = bs(open(file), 'html.parser')
        all_files = get_links(soup)
        fixed_dates = fix_dates(all_files)
        all_files = all_files + fixed_dates
        available_files = audio_video("Audio", all_files, complete_files)
        available_files = remove_duplicates(available_files)
        to_database(available_files)


def fix_dates(all_files):
    lst = []
    for file in all_files:
        if "19" in file[0][:2] or "2" in file[0][:1] or "12" in file[0][:2]:
            pass
        else:
            if re.match(date_check, file[1]):
                fixed_date = file[0].split(" ")
                if "0" in fixed_date[-1]:
                    fixed_date = "20{}{}{}".format(fixed_date[-1], *fixed_date[:2])
                else:
                    fixed_date = "19{}{}{}".format(fixed_date[-1], *fixed_date[:2])
                fixed_name = file[1].split(" ", 3)
                name_end = fixed_name[-1]
                if "0" in fixed_name[-2]:
                    fixed_name = "20{}{}{}{}".format(fixed_name[-2], fixed_name[0], fixed_name[1], name_end)
                else:
                    fixed_name = "19{}{}{}{}".format(fixed_name[-2], fixed_name[0], fixed_name[1], name_end)
                lst.append((fixed_date, fixed_name, file[-1]))
    return lst


def get_links(soup):
    empty_list = []
    for link in soup.find_all('a'):
        try:
            empty_list.append((link.string.lstrip()[0:8],
                               link.string.strip().replace("\n", "").replace("\t", ""),
                               link.get('href').strip()))
        except AttributeError:
            pass
    return empty_list


def done_files():
    """
    returns all dates from validtranscripts.txt
    :rtype: list
    """
    complete_files = []
    with open("validtranscripts.txt", 'r') as file:
        for line in file:
            complete_files.append(line[:8])
        return complete_files


def audio_video(option, all_files, complete_files):
    available_files = []
    for file in all_files:
        if file[0] not in complete_files:
            if re.match(valid_string, file[0]):
                if option == "Video":
                    # print("Date: {} | Full: {} | Link: {}".format(file[0], normalize(file), file[-1]))
                    available_files.append({"file_name": file[1], "file_link": file[2], "file_type": "Video"})
                else:
                    if not file[0][:4] == "1996":
                        available_files.append((file[0], file[1], file[2]))
    return available_files


def check_files(available_files):
    for x in available_files:
        print(x)


def remove_duplicates(available_files):
    clean_files = []
    for idx, item in enumerate(available_files):
        if idx > 0:
            previous = available_files[idx-1]
            current = item
            if previous[0] + normalize(previous[1]) == current[0] + normalize(current[1]):
                pass
            else:
                clean_files.append({"file_name": previous[1], "file_link": previous[2], "file_type": "Audio"})
    return clean_files


def to_database(available_files):
    with DATABASE.atomic():
        for idx in range(0, len(available_files), 100):
            try:
                GetStarted.insert_many(available_files[idx:idx+100]).execute()
            except IntegrityError:
                # print(available_files[idx])
                pass
