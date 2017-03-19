#
# import os
#
# dir_path = os.path.dirname(os.path.realpath(__file__))
# sep = os.path.sep
#
# print(dir_path)

import requests

r = requests.get("https://graph.facebook.com/v2.8/129707793744605_1244539492261424/likes?access_token=EAACEdEose0cBAJxjCKXmhNadXkytDb9BIPkZBXpfPtZCWEjXETbDmPIKQMVZBBLKj2pbj5ZAJXinzbn9FwWxf0t7RyaPBmv3s89Hh8CYDE9PhLujfajyTv3HNdOUTllHXl2AjBdjhlFV8zOWjA0ZANQ7A4KO0xR5FqywdQ0eZBIMkNVfHwJEZAnoFsPQ1xbJIQZD&limit=1000")

print(r.json())

new_request = requests.get(r.json()['paging']['next'])
print("\n")

print(new_request.json())

next_request = requests.get(new_request.json()['paging']['next'])

print("\n")
print(next_request.json())
