# Copyright Craig Hamilton
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, UTC
from pathlib import Path
from typing import Tuple, List

from dotenv import load_dotenv

import smugmug_auth as smugmug

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())

# Loads the API Key and Token cache from a .env file
load_dotenv()


class SmugMugIf:
    """
    Provides a medium level interface to the SmugMug API.
    ATM this is an attempt to potentially be the start of a SmugMug library
    but not quite getting it generic enough yet.
    """

    def __init__(self):
        config = {
            "key": os.getenv("SMUGMUG_API_KEY"),
            "secret": os.getenv("SMUGMUG_API_SECRET"),
        }
        tokenfn = Path(os.getenv("SMUGMUG_AUTH_CACHE"))

        self.session = smugmug.auth(config, tokenfn)

    def _make_get_request(self, uri_str: str, **kwargs) -> dict:
        """
        Performs a GET request to the SmugMug API.
        :param uri_str: URI endpoint to be called.
        :param kwargs: Optional parameters to allow API return behaviour.
        :return: The response if successful otherwise will throw with the error code and log the
        error response.
        """
        session_params = {"headers": {"Accept": "application/json"}, **kwargs}
        # log.info(f"Req URI: {uri_str},  Params: {session_params}")
        resp = json.loads(self.session.get(uri_str, **session_params).text)
        # log.debug(f"Raw Resp:\n {json.dumps(resp,indent=4)}\n")
        resp_code = resp["Code"]
        if 200 != resp_code:
            log.error(f"Error in Raw Resp:\n {json.dumps(resp,indent=4)}\n")
            resp_msg = resp["Message"]
            raise RuntimeError(f"Request Failed! Code: {resp_code} Msg: {resp_msg}")
        return resp

    def _make_patch_request(self, uri_str: str, data: dict, **kwargs) -> dict:
        """
        Performs a PATCH request to the SmugMug API.
        :param uri_str: URI endpoint to be called.
        :param data: a dictionary of properties to be changed.
        :param kwargs: Optional parameters to allow API return behaviour.
        :return: The response if successful otherwise will throw with the error code and log the
        error response.
        """
        session_params = {
            "headers": {
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            **kwargs,
        }
        data_json_str = json.dumps(data)
        log.debug(
            f"Req URI: {uri_str},  Params: {session_params},  Data: {data_json_str}"
        )
        resp = json.loads(
            self.session.patch(uri_str, data=data_json_str, **session_params).text
        )
        log.debug(f"Raw Resp:\n {json.dumps(resp,indent=4)}\n")
        resp_code = resp["Code"]
        if 200 != resp_code:
            log.error(f"Error in Raw Resp:\n {json.dumps(resp,indent=4)}\n")
            resp_msg = resp["Message"]
            raise RuntimeError(f"Request Failed! Code: {resp_code} Msg: {resp_msg}")
        return resp

    def user_info(self) -> dict:
        """
        Retrieves the user information for the currently authenticated user.
        :return: Returns the user information.
        """
        uri_str = smugmug.API_ORIGIN + "/api/v2!authuser"
        params = {"_verbosity": "1"}
        auth_info = self._make_get_request(uri_str, params=params)
        log.debug(f"Auth Resp:\n {json.dumps(auth_info,indent=4)}\n")
        return auth_info["Response"]["User"]

    def get_node_children(
        self, node_uri: str, count: int | None = None, start: int | None = None
    ) -> dict:
        """
        Retrieves children off the specified node.
        :param node_uri: Node URI for a Node object to be acted on.
        :param count: Number of node children to be retrieved.
        :param start: Index of node children to start from.
        :return: Returns an array of the found Node children.
        """
        uri_str = smugmug.API_ORIGIN + f"{node_uri}!children"
        params = {
            "_verbosity": "1",
            "Type": "Album",
            "SortMethod": "Organizer",
            "SortDirection": "Descending",
        }
        if count is not None:
            params["count"] = count
        if start is not None:
            params["start"] = start

        child_nodes_resp = self._make_get_request(uri_str, params=params)

        log.debug(f"Get Child Nodes Resp:\n {json.dumps(child_nodes_resp,indent=4)}\n")
        return child_nodes_resp["Response"].get("Node", [])

    def get_album_info(self, album_uri: str) -> dict:
        """
        Retrieves information about an album.
        :param album_uri: The Album URI to get information about.
        :return: the Album information object.
        """
        uri_str = smugmug.API_ORIGIN + f"{album_uri}"
        album_info_resp = self._make_get_request(uri_str)
        log.debug(f"Get Album Resp:\n {json.dumps(album_info_resp,indent=4)}\n")
        return album_info_resp["Response"]["Album"]

    def change_album_info(self, album_uri: str, data: dict) -> dict:
        """
        Changes Album properties.
        :param album_uri: The Album URI to get information about.
        :param data: The properties to be updated.
        :return:
        """
        params = {
            "_verbosity": "1",
        }
        uri_str = smugmug.API_ORIGIN + f"{album_uri}"
        album_info_resp = self._make_patch_request(uri_str, data, params=params)
        log.debug(f"Patch Album Resp:\n {json.dumps(album_info_resp,indent=4)}\n")
        return album_info_resp["Response"]["Album"]


@dataclass
class AlbumInfo:
    """
    Holds information about an Album needed for other operations
    """

    name: str
    uri: str
    created: datetime
    upload_key: str


def get_albums_with_expired_upload_keys(
    smugmug_if: SmugMugIf, node_uri: str, count=50, start=None
) -> Tuple[bool, List[AlbumInfo]]:
    """
    Retrieves Albums that are older than 60 days and have Upload keys
    :param smugmug_if: Instance of a SmugMugIf
    :param node_uri: Root node URI to act on
    :param count: Number of records to retrieve
    :param start: Index of records to start from
    :return: a tuple where index 0 is if there are more records and index 1 is list of albums to update
    """
    current_dt = datetime.now(UTC)

    album_with_expired_upload_keys = []
    child_nodes = smugmug_if.get_node_children(node_uri, count, start)
    is_more = len(child_nodes) != 0
    for node in child_nodes:
        if "Album" != node["Type"]:
            continue
        name = node["Name"]
        album_uri = node["Uris"]["Album"]
        log.info(f"Getting information for: {name}")
        album_info = smugmug_if.get_album_info(album_uri)
        upload_key = album_info.get("UploadKey", "")

        created_dt = datetime.fromisoformat(album_info["Date"])
        diff_dt = current_dt - created_dt

        if len(upload_key) != 0 and diff_dt.days > 60:
            album_to_update = AlbumInfo(name, album_uri, created_dt, upload_key)
            album_with_expired_upload_keys.append(album_to_update)

    return is_more, album_with_expired_upload_keys


def remove_upload_key_from_album(smugmug_if: SmugMugIf, album: AlbumInfo):
    """
    Updates an Album to remove the UploadKey entry
    :param smugmug_if: Instance of a SmugMugIf
    :param album: Album URI to act upon
    :return: None but will throw if error happens in update
    """
    log.info(f"Removing UploadKey from: {album.name} uri: {album.uri}")
    data = {"UploadKey": ""}
    smugmug_if.change_album_info(album.uri, data)


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    log.info("SmugMug Upload URI Scrubber")

    # Instantiate the SmugMugIf
    smugmug_if = SmugMugIf()

    # Get current user information (like the root node)
    user_info = smugmug_if.user_info()
    root_node_uri = user_info["Uris"]["Node"]

    # Go through the pages of albums and if any need updating then update them
    start_at = 0
    num_to_get = 50
    while True:

        log.info(f"Getting {num_to_get} albums at index {start_at}")
        is_more, albums_to_update = get_albums_with_expired_upload_keys(
            smugmug_if, root_node_uri, num_to_get, start_at
        )

        log.debug(f"Albums with expired upload keys: {albums_to_update}")
        for album in albums_to_update:
            remove_upload_key_from_album(smugmug_if, album)

        # If there are not more records the break out of the loop
        if not is_more:
            break

        # Update start_at to get the next page
        start_at = start_at + num_to_get
