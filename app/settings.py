#  Polkascan PRE Explorer API
#
#  Copyright 2018-2019 openAware BV (NL).
#  This file is part of Polkascan.
#
#  Polkascan is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Polkascan is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with Polkascan. If not, see <http://www.gnu.org/licenses/>.
#
#  settings.py
import os

DB_NAME = os.environ.get("DB_NAME", "polkascan")
DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT = os.environ.get("DB_PORT", 3306)
DB_USERNAME = os.environ.get("DB_USERNAME", "root")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "root")

DB_CONNECTION = os.environ.get("DB_CONNECTION", "mysql+mysqlconnector://{}:{}@{}:{}/{}".format(
    DB_USERNAME, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME
))

SUBSTRATE_RPC_URL = os.environ.get("SUBSTRATE_RPC_URL", "http://192.168.1.242:9933/")
SUBSTRATE_ADDRESS_TYPE = int(os.environ.get("SUBSTRATE_ADDRESS_TYPE", 42))
SUBSTRATE_METADATA_VERSION = int(os.environ.get("SUBSTRATE_METADATA_VERSION", 3))
SHARDS_TABLE = {"shard.0": "http://192.168.1.68:9930/", "shard.1": "http://192.168.1.68:9931/",
                "shard.2": "http://192.168.1.135:9932/", "shard.3": "http://192.168.1.135:9933/"}
TYPE_REGISTRY = os.environ.get("TYPE_REGISTRY", "default")
HRP = os.environ.get("HRP", "tyee")

DOGPILE_CACHE_SETTINGS = {

    'default_list_cache_expiration_time': 6,
    'default_detail_cache_expiration_time': 3600,
    'host': os.environ.get("DOGPILE_CACHE_HOST", "redis"),
    'port': os.environ.get("DOGPILE_CACHE_HOST", 6379),
    'db': os.environ.get("DOGPILE_CACHE_DB", 10)
}


DEBUG = False

MAX_RESOURCE_PAGE_SIZE = 100
LOG_TYPE_AUTHORITIESCHANGE = 1

try:
    from app.local_settings import *
except ImportError:
    pass
