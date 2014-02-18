# -*- coding: utf-8 -*-
#
# This file is part of ZENODO.
# Copyright (C) 2014 CERN.
#
# ZENODO is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ZENODO is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ZENODO. If not, see <http://www.gnu.org/licenses/>.
#
# In applying this licence, CERN does not waive the privileges and immunities
# granted to it by virtue of its status as an Intergovernmental Organization
# or submit itself to any jurisdiction.


"""
GitHub blueprint for Zenodo
"""

from __future__ import absolute_import

import json

from flask import current_app
import requests

from invenio.ext.sqlalchemy import db
from invenio.ext.email import send_email
from invenio.config import CFG_SITE_ADMIN_EMAIL
from invenio.ext.template import render_template_to_string
from invenio.modules.accounts.models import User
from invenio.modules.webhooks.models import Event
from invenio.celery import celery
from zenodo.ext.oauth import oauth

from ..models import OAuthTokens


# TODO: Send requests checking SSL certificate (zenodo-dev certificate expired!)
# TODO: Move to celery task
# TODO: Break out into multiple functions
# TODO: Ensure duplicate releases are not created.
@celery.task(ignore_result=True)
def create_deposition(event_state):
    remote = oauth.remote_apps['github']

    e = Event()
    e.__setstate__(event_state)

    user_id = e.user_id
    user_email = User.query.filter_by(id=user_id).first().email
    payload = e.payload
    user = OAuthTokens.query.filter_by(user_id=user_id).filter_by(
        client_id=remote.consumer_key
    ).first()

    release = payload["release"]
    repository = payload["repository"]
    repository_name = repository["full_name"]

    # GitHub sends a small test payload when the hook is created. Avoid creating
    # a deposition from it.
    if 'hook_id' in payload:
        return json.dumps({"state": "hook-added"})

    api_key = current_app.config["ZENODO_API_KEY"]
    zenodo_api = "https://zenodo-dev.cern.ch/api"

    # First create an empty deposition and attach metadata later.
    headers = {"Content-Type": "application/json"}
    r = requests.post(
        "%(api)s/deposit/depositions?apikey=%(api_key)s" % {
            "api": zenodo_api, "api_key": api_key},
        data="{}",
        headers=headers,
        verify=False
    )

    if r.status_code is not 201:
        # The deposition was not created. Make note in extra_data and notify user
        # user.extra_data["repos"][repository_name]["error"] = "deposition not created"
        # user.extra_data.update()
        # db.session.commit()
        return json.dumps({"error": "deposition was not created"})

    # The deposition has been created successfully.
    deposition_id = r.json()['id']

    # At this point we need to get metadata. Since we require the user to include a .zenodo.json file in the repository,
    # we'll fetch it here, or prompt the user to supply metadata via an email
    # notification.

    # Format the raw url from the release payload
    zenodo_json_path = payload["release"]["html_url"]
    zenodo_json_path = zenodo_json_path.replace("github.com", "raw.github.com")
    zenodo_json_path = zenodo_json_path.replace("releases/tag/", '')
    zenodo_json_path += "/.zenodo.json"

    # Get the .zenodo.json file
    r = requests.get(zenodo_json_path)
    if r.status_code is 200:

        zenodo_metadata = {"metadata": json.loads(r.text)}
        r = requests.put(
            "%(api)s/deposit/depositions/%(deposition_id)s?apikey=%(api_key)s"
            % {"api": zenodo_api, "deposition_id": deposition_id, "api_key": api_key},
            data=json.dumps(zenodo_metadata),
            headers=headers,
            verify=False
        )

    # TODO: Handle other status codes
    else:
        # Notify user when there is no .zenodo.json file in the repository.
        send_email(
            CFG_SITE_ADMIN_EMAIL,
            user_email,
            subject="Metadata Needed For Deposition",
            content=render_template_to_string(
                "github/email_zenodo_json.html"
            )
        )

    # Download the archive
    archive_url = release["zipball_url"]
    archive_name = "%(repo_name)s-%(tag_name)s.zip" % {
        "repo_name": repository["name"], "tag_name": release["tag_name"]}

    r = requests.get(archive_url, stream=True)
    if r.status_code is 200:
        with open(archive_name, 'wb') as fd:
            for chunk in r.iter_content(256):
                fd.write(chunk)

    # Append the file to the deposition
    data = {'filename': archive_name}
    files = {'file': open(archive_name, 'rb')}
    r = requests.post(
        "%(api)s/deposit/depositions/%(deposition_id)s/files?apikey=%(api_key)s" %
        {"api": zenodo_api, "deposition_id":
            deposition_id, "api_key": api_key},
        data=data,
        files=files,
        verify=False
    )
    if r.status_code is not 201:
        # TODO: Write email stating that upload of file has failed.
        return json.dumps({"error": "file was not added to deposition"})

    # Publish the deposition!
    r = requests.post(
        "%(api)s/deposit/depositions/%(deposition_id)s/actions/publish?apikey=%(api_key)s" %
        {"api": zenodo_api, "deposition_id":
            deposition_id, "api_key": api_key},
        verify=False
    )

    # Add to extra_data
    user = OAuthTokens.query.filter_by(user_id=user_id).filter_by(
        client_id=remote.consumer_key).first()
    user.extra_data["repos"][repository_name]["DOI"] = r.json()["doi"]
    user.extra_data["repos"][repository_name][
        "modified"] = r.json()["modified"]
    user.extra_data.update()
    db.session.commit()

    if r.status_code is 202:
        return json.dumps({"state": "deposition added successfully"})

    return json.dumps({"state": "deposition not published"})
