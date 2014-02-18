# -*- coding: utf-8 -*-
#
## This file is part of ZENODO.
## Copyright (C) 2014 CERN.
##
## ZENODO is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
##
## ZENODO is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with ZENODO. If not, see <http://www.gnu.org/licenses/>.
##
## In applying this licence, CERN does not waive the privileges and immunities
## granted to it by virtue of its status as an Intergovernmental Organization
## or submit itself to any jurisdiction.


"""
GitHub blueprint for Zenodo
"""

from __future__ import absolute_import

import os
import json
import pytz
import dateutil
from dateutil.parser import parse
from datetime import datetime, timedelta

import humanize
import requests
from flask import Blueprint, render_template, redirect, url_for, session, request, jsonify, current_app
from flask.ext.login import current_user

from invenio.ext.sqlalchemy import db
from invenio.ext.email import send_email
from invenio.modules.oauth2server.provider import oauth2
from invenio.config import CFG_SITE_ADMIN_EMAIL, CFG_SITE_NAME
from invenio.ext.template import render_template_to_string
from invenio.modules.accounts.models import User
from invenio.modules.oauth2server.models import Token
from zenodo.ext.oauth import oauth

from .models import OAuthTokens


remote = oauth.remote_apps['github']
blueprint = Blueprint(
    'zenodo_github',
    __name__,
    static_folder="static",
    template_folder="templates",
    url_prefix="/github"
)

# TODO: Place this module behind a Zenodo authorized URL


@blueprint.app_template_filter('naturaltime')
def naturaltime(val):
    val = parse(val)
    now = datetime.utcnow().replace(tzinfo = pytz.utc)
    
    return humanize.naturaltime(now - val)

def get_repositories(user):
    """Helper method to get a list of current user's repositories from GitHub."""
    r = remote.get("users/%(username)s/repos?type=owner&sort=full_name" % {"username": session["github_login"]})
    
    repo_data = r.data
    def get_repo_name(repo): return repo["full_name"]
    def get_repo_data(repo): return { "hook": None, "description": repo["description"] }
    
    repo_names = map(get_repo_name, repo_data)
    repo_data = map(get_repo_data, repo_data)
    repos = dict( \
        zip(repo_names, repo_data) \
    )
    
    if user is not None:
        extra_data = user.extra_data
    
        # Map the existing data with the fresh dump from GitHub
        for name, description in repos.iteritems():
            if name in extra_data["repos"]:
                repos[name] = extra_data["repos"][name]
    
    return {
        "repos_last_sync": str(datetime.now()),
        "repos": repos
    }

@blueprint.route('/')
def index():
    context = { "connected": False }

    # Check if user has already authorized GitHub
    user = OAuthTokens.query \
        .filter_by( user_id = current_user.get_id() ) \
        .filter_by( client_id = remote.consumer_key ) \
        .first()

    if user is not None:

        # The user has previously been authenticated. Check if the token is still valid.
        # GitHub requires the use of Basic Auth to query token validity. Valid responses return 200.
        r = requests.get(
            "https://api.github.com/applications/%(client_id)s/tokens/%(access_token)s" % \
            {"client_id": remote.consumer_key, "access_token": user.access_token},
            auth=(remote.consumer_key, remote.consumer_secret)
        )

        if r.status_code == 200:
            # The user is authenticated and the token we have is still valid. Render GitHub settings page.
            extra_data = user.extra_data

            # Add information to session
            session["github_token"] = (user.access_token, '')
            session["github_login"] = extra_data['login']

            # Check the date of the last repo sync
            last_sync = datetime.strptime( \
                extra_data["repos_last_sync"], \
                "%Y-%m-%d %H:%M:%S.%f"
            )
            today = datetime.now()
            yesterday = today - timedelta(days = 1)
            if last_sync < yesterday:
                repos = get_repositories(user)
                user.extra_data.update(repos)
                db.session.commit()
            
            context["connected"] = True
            context["repos"] = extra_data['repos']
            context["name"] = extra_data['login']
            context["last_sync"] = humanize.naturaltime(datetime.now() - last_sync)

    return render_template("github/index.html", **context)

# Authenticated endpoint
@blueprint.route('/connect')
def connect():
    return remote.authorize(
        callback = url_for('.connected', _external = True)
    )

# Authenticated endpoint
@blueprint.route('/connected')
@remote.authorized_handler
def connected(resp):
    current_user_id = current_user.get_id()

    # TODO: Better error handling. If GitHub auth fails, we'll get a Bad Request (400)
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )

    # Store the GitHub access token on the session
    github_token = resp['access_token']
    session['github_token'] = (github_token, '')

    # Check if the user has previously created a GitHub OAuth token
    user = OAuthTokens.query \
        .filter_by( user_id = current_user.get_id() ) \
        .filter_by( client_id = remote.consumer_key ) \
        .first()
    if user is None:

        # Get user data
        resp = remote.get('user')
        github_login = resp.data['login']
        github_name = resp.data['name']
        
        # Create a Zenodo personal access token
        zenodo_token = Token.create_personal('github', current_user_id)
        
        extra_data = get_repositories(user)
        extra_data.update({
            "login": github_login,
            "name": github_name,
            "zenodo_token_id": zenodo_token.id            
        })
        
        # Put user's GitHub info in database
        o = OAuthTokens(
            client_id = remote.consumer_key,
            user_id = current_user.get_id(),
            access_token = github_token,
            extra_data = extra_data
        )
        db.session.add(o)
    else:
        # User has previously connected to the GitHub client. Update the token.
        user.access_token = github_token
        github_login = user.extra_data['login']
        github_name = user.extra_data['name']

    db.session.commit()

    return redirect( url_for('.index') )

# TODO: Authenticated endpoint
@blueprint.route('/remove-github-hook', methods=["POST"])
def remove_github_hook():
    status = {"status": False}
    repo = request.json["repo"]
    
    # Get the hook id from the database
    user = OAuthTokens.query.filter_by(user_id = current_user.get_id()).filter_by(client_id = remote.consumer_key).first()
    hook_id = user.extra_data["repos"][repo]["hook"]

    resp = remote.delete(
        "repos/%(full_name)s/hooks/%(hook_id)s" % {"full_name": repo, "hook_id": hook_id},
    )

    if resp.status == 204:
        # The hook has successfully been removed by GitHub, update the status and DB
        status["status"] = True
        
        user.extra_data["repos"][repo]["hook"] = None
        user.extra_data.update()
        db.session.commit()

    return json.dumps(status)

# TODO: Authenticated endpoint
@blueprint.route('/create-github-hook', methods=["POST"])
def create_github_hook():
    status = {"status": False}
    repo = request.json["repo"]
    
    user = OAuthTokens.query.filter_by(user_id = current_user.get_id()).filter_by(client_id = remote.consumer_key).first()
    github_login = user.extra_data["login"]
    zenodo_token_id = Token.query.filter_by(id = user.extra_data["zenodo_token_id"]).first().access_token
    
    # TODO: Use Zenodo endpoint instead of Ultrahook!!!
    data = {
        "name": "web",
        "config": {
            "url": "http://github.zenodo.ultrahook.com?access_token=%(token)s" % {"token": zenodo_token_id},
            "content_type": "json"
        },
        "events": ["release"],
        "active": True
    }

    resp = remote.post(
        "repos/%(full_name)s/hooks" % {"full_name": repo},
        format='json',
        data=data
    )
    
    
    if resp.status == 201:
        # Hook was created, updated the status and database
        status["status"] = True
        
        user.extra_data["repos"][repo]["hook"] = resp.data["id"]
        user.extra_data.update()
        db.session.commit()

    return json.dumps(status)

# TODO: Authenticated endpoint
@blueprint.route('/sync', methods=["GET"])
def sync_repositories():

    # Query for our current repo data
    user = OAuthTokens.query.filter_by( user_id = current_user.get_id() ).filter_by( client_id = remote.consumer_key ).first()
    if user is None:
        return json.dumps({"state": "error syncing"})

    repos = get_repositories(user)
    user.extra_data.update(repos)
    db.session.commit()

    return redirect( url_for('.index') )


def create_deposition_error():
    """docstring for create_deposition_error"""
    pass
    

# TODO: Send requests checking SSL certificate (zenodo-dev certificate expired!)
# TODO: Move to celery task
# TODO: Break out into multiple functions
# TODO: Ensure duplicate releases are not created.
@blueprint.route('/create-deposition', methods=["POST"])
@oauth2.require_oauth()
def create_deposition(data):
    user_id = data.user.id
    user_email = data.email
    payload = request.json
    user = OAuthTokens.query.filter_by( user_id = user_id ).filter_by( client_id = remote.consumer_key ).first()
    
    # GitHub sends a small test payload when the hook is created. Avoid creating
    # a deposition from it.
    if 'hook_id' in payload:
        return json.dumps({"state": "hook-added"})

    release = payload["release"]
    repository = payload["repository"]
    repository_name = repository["full_name"]
    errors = []

    api_key = current_app.config["ZENODO_API_KEY"]
    zenodo_api = "https://zenodo-dev.cern.ch/api"
    zenodo_token = request.args.get('access_token')
    
    #
    #   Step 1: Create an empty deposition
    #
    
    headers = {"Content-Type": "application/json"}
    r = requests.post(
        "%(api)s/deposit/depositions?apikey=%(api_key)s" % {"api": zenodo_api, "api_key": api_key},
        data="{}",
        headers=headers,
        verify=False
    )
    
    # Check if the deposition was created. When errors, make note on the extra_data and notify owner.
    # TODO: Email notification to owner
    if r.status_code != 201:
        
        # The deposition was not created. Make note in extra_data and notify user
        errors.append({"message": "Deposition was not created."})
        user.extra_data["repos"][repository_name]["errors"] = errors
        user.extra_data.update()
        
        db.session.commit()
        return json.dumps( {"errors": errors} )
    
    #
    #   Step 2: Get and attach metadata to deposition
    #
    
    # The deposition has been created successfully.
    deposition_id = r.json()['id']
    
    # At this point we need to get metadata. Since we require the user to include a .zenodo.json file in the repository,
    # we'll fetch it here, or prompt the user to supply metadata via an email notification.

    # Format the raw url from the release payload
    zenodo_json_path = payload["release"]["html_url"]
    zenodo_json_path = zenodo_json_path.replace("github.com", "raw.github.com")
    zenodo_json_path = zenodo_json_path.replace("releases/tag/", '')
    zenodo_json_path += "/.zenodo.json"

    # Get the .zenodo.json file
    r = requests.get(zenodo_json_path)
    if r.status_code == 200:

        zenodo_metadata = { "metadata": json.loads(r.text) }
        r = requests.put(
            "%(api)s/deposit/depositions/%(deposition_id)s?apikey=%(api_key)s" \
            % {"api": zenodo_api, "deposition_id": deposition_id, "api_key": api_key},
            data=json.dumps(zenodo_metadata),
            headers=headers,
            verify=False
        )
        
        # The metadata file contains errors
        if r.status_code == 400:
            
            # Metadata was not attached due to malformed .zenodo.json file. Append to errors and notify via email.
            errors = errors + r.json()["errors"]
            
            send_email(
                CFG_SITE_ADMIN_EMAIL,
                user_email,
                subject="Metadata Needed For Deposition",
                content=render_template_to_string(
                    "github/email_zenodo_json.html"
                )
            )

    else:
        
        # There's no zenodo.json file in the repository. Append to errors and
        # notify owner for additional metadata.
        errors.append(
            {"message": "Missing .zenodo.json metadata file from repository."}
        )
        
        # Notify user when there is no .zenodo.json file in the repository.
        send_email(
            CFG_SITE_ADMIN_EMAIL,
            user_email,
            subject="Metadata Needed For Deposition",
            content=render_template_to_string(
                "github/email_zenodo_json.html"
            )
        )
    
    #
    #   Step 3: Get the archive file
    #
    
    # Download the archive
    archive_url = release["zipball_url"]
    archive_name = "%(repo_name)s-%(tag_name)s.zip" % {"repo_name": repository["name"], "tag_name": release["tag_name"]}

    r = requests.get(archive_url, stream=True)
    if r.status_code == 200:

        # Append the file to the deposition
        data = {'filename': archive_name}
        files = {"file": r.raw}
        
        r = requests.post(
            "%(api)s/deposit/depositions/%(deposition_id)s/files?apikey=%(api_key)s" % \
            {"api": zenodo_api, "deposition_id": deposition_id, "api_key": api_key},
            data=data,
            files=files,
            verify=False
        )
        
        if r.status_code != 201:
            errors.append(
                {"message": "Could not upload the archive to Zenodo."}
            )
    else:
        
        # There was trouble getting the archive from GitHub
        errors.append(
            {"message": "Could not retrieve the archive from GitHub."}
        )
    
    #
    #   Step 4: Publish to Zenodo for wicked software preservation!
    #
    
    if len(errors) == 0:
        
        r = requests.post(
            "%(api)s/deposit/depositions/%(deposition_id)s/actions/publish?apikey=%(api_key)s" % \
            {"api": zenodo_api, "deposition_id": deposition_id, "api_key": api_key},
            verify=False
        )
        
        if r.status_code == 202:
            user.extra_data["repos"][repository_name]["doi"] = r.json()["doi"]
            user.extra_data["repos"][repository_name]["modified"] = r.json()["modified"]
            user.extra_data.update()
            db.session.commit()
            
            return json.dumps({"state": "deposition added successfully"})
        
        errors.append(
            {"message": "Deposition could not be published to Zenodo."}
        )

    # Add to extra_data
    user.extra_data["repos"][repository_name]["errors"] = errors
    user.extra_data.update()
    db.session.commit()

    return json.dumps({"state": "deposition not successful"})


@remote.tokengetter
def get_oauth_token():
    return session.get('github_token')
