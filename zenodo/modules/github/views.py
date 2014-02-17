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
from datetime import datetime

import requests
from flask import Blueprint, render_template, redirect, url_for, session, request, jsonify
from flask.ext.login import current_user

from invenio.ext.sqlalchemy import db
from invenio.ext.email import send_email
from invenio.config import CFG_SITE_ADMIN_EMAIL, CFG_SITE_NAME
from invenio.ext.template import render_template_to_string
from invenio.modules.accounts.models import User
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

# Authenticated endpoint
@blueprint.route('/')
def index():
    context = { "connected": False }
    
    # Check if user has already authorized GitHub
    user = OAuthTokens.query.filter_by( user_id = current_user.get_id() ).filter_by( client_id = remote.consumer_key ).first()
    
    if user is not None:
        
        # The user has previously been authenticated. Check if the token is still valid.
        # GitHub requires the use of Basic Auth to query token validity. Valid responses return 200.
        endpoint = "https://api.github.com/applications/%(client_id)s/tokens/%(access_token)s" % {"client_id": remote.consumer_key, "access_token": user.access_token}
        r = requests.get(endpoint, auth=(remote.consumer_key, remote.consumer_secret))
        
        if r.status_code is 200:
            # The user is authenticated and the token we have is still valid. Render GitHub setting page.
            extra_data = user.extra_data
            
            # Add information to session
            session["github_token"] = (user.access_token, '')
            session["github_login"] = extra_data['login']
            
            context["connected"] = True
            context["repos"] = extra_data['repos']
            context["name"] = extra_data['login']
            
            print "EXTRA_DATA", extra_data
    
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
    
    # TODO: Better error handling. If GitHub auth fails, we'll get a Bad Request (400)
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    
    # Store the access token on the session
    token = resp['access_token']    
    session['github_token'] = (token, '')
    
    # Check if the user has previously created a GitHub OAuth token
    user = OAuthTokens.query.filter_by(user_id = current_user.get_id()).filter_by(client_id = remote.consumer_key).first()
    if user is None:
        
        # Get user data
        resp = remote.get('user')
        github_login = resp.data['login']
        github_name = resp.data['name']
        
        # Get repo data and format JSON
        resp = remote.get("users/%(username)s/repos" % {"username": github_login})
        repos = resp.data
        
        def get_repo_name(repo): return repo["name"]
        repos = map(get_repo_name, repos)
        repos = dict(zip(repos, [{ "hook": None } for _ in xrange(len(repos))]))
        
        # Put user's GitHub info in database
        o = OAuthTokens(
            client_id = remote.consumer_key,
            user_id = current_user.get_id(),
            access_token = token,
            extra_data = {"login": github_login, "name": github_name, "repos": repos}
        )
        db.session.add(o)
    else:
        # User has previously connected to the GitHub client. Update the token.
        user.access_token = token
        github_login = user.extra_data['login']
        github_name = user.extra_data['name']
    
    db.session.commit()
    session["github_login"] = github_login
    session["github_name"] = github_name
    
    return redirect( url_for('.index') )

# TODO: Authenticated endpoint
@blueprint.route('/remove-github-hook/<repo>', methods=["POST"])
def remove_github_hook(repo):
    
    # Get the hook id from the database
    user = OAuthTokens.query.filter_by(user_id = current_user.get_id()).filter_by(client_id = remote.consumer_key).first()
    hook_id = user.extra_data["repos"][repo]["hook"]
    
    endpoint = "repos/%(owner)s/%(repo)s/hooks/%(hook_id)s" % {"owner": session["github_login"], "repo": repo, "hook_id": hook_id}
    resp = remote.delete(endpoint)
    
    if resp.status is 204:
        # The hook has successfully been removed by GitHub, so update the user's entry
        user.extra_data["repos"][repo]["hook"] = None
        user.extra_data.update()
        db.session.commit()
    
    return json.dumps({"state": "removed"})

# TODO: Authenticated endpoint
@blueprint.route('/create-github-hook/<repo>', methods=["POST"])
def create_github_hook(repo):
    endpoint = "repos/%(owner)s/%(repo)s/hooks" % {"owner": session["github_login"], "repo": repo}
    
    # TODO: Use Zenodo API
    data = {
        "name": "web",
        "config": {
            # TODO: Update to pass in token instead of Zenodo user id
            "url": "http://github.zenodo.ultrahook.com?token=%(token)s" % {"token": current_user.get_id()},
            "content_type": "json"
        },
        "events": ["release"],
        "active": True
    }
    print "HERE", data
    
    resp = remote.post(endpoint, format='json', data=data)
    if resp.status is 201:
        
        # Hook was created, so update the database storing the hook id
        user = OAuthTokens.query.filter_by(user_id = current_user.get_id()).filter_by(client_id = remote.consumer_key).first()
        user.extra_data["repos"][repo]["hook"] = resp.data["id"]
        user.extra_data.update()
        db.session.commit()
    
    return json.dumps({"state": "added"})


# TODO: Authenticated endpoint
@blueprint.route('/sync', methods=["GET"])
def sync_repositories():
    
    resp = remote.get("users/%(username)s/repos" % {"username": session["github_login"]})
    if resp.status is not 200:
        return json.dumps({"state": "error syncing"})
    
    # Query for our current repo data
    user = OAuthTokens.query.filter_by( user_id = current_user.get_id() ).filter_by( client_id = remote.consumer_key ).first()
    if user is None:
        return json.dumps({"state": "error syncing"})
    
    extra_data = user.extra_data
    
    repos = resp.data
    def get_repo_name(repo): return repo["name"]
    repos = map(get_repo_name, repos)
    repos = dict(zip(repos, [{ "hook": None } for _ in xrange(len(repos))]))
    
    # Map the existing data with the fresh dump from GitHub
    for name, description in repos.iteritems():
        if name in extra_data["repos"]:
            repos[name] = extra_data["repos"][name]
    
    user.extra_data["repos"] = repos
    user.extra_data.update()
    db.session.commit()
    
    return redirect( url_for('.index') )

# TODO: Send requests checking SSL certificate (zenodo-dev certificate expired!)
# TODO: Move to celery task
# TODO: Break out into multiple functions
@blueprint.route('/create-deposition', methods=["POST"])
def create_deposition():
    payload = request.json
    
    # GitHub sends a small test payload when the hook is created. Avoid creating
    # a deposition from it.
    if 'hook_id' in payload:
        return json.dumps({"state": "hook-added"})
    
    api_key = os.environ["ZENODO_API_KEY"]
    zenodo_api = "https://zenodo-dev.cern.ch/api"
    token = request.args.get('token') # TODO: apply authorization decorator above
    
    # First create an empty deposition and attach metadata later.
    headers = {"Content-Type": "application/json"}
    r = requests.post(
        "%(api)s/deposit/depositions?apikey=%(api_key)s" % {"api": zenodo_api, "api_key": api_key},
        data="{}",
        headers=headers,
        verify=False
    )
    
    if r.status_code is not 201:
        # The deposition was not created. What's a good behavior here?!?!
        # Send notification to user?
        return json.dumps({"error": "deposition was not created"})
    
    # The deposition has been created successfully.
    deposition_id = r.json()['id']
    
    # At this point we need to get metadata. Since we require the user to include a zenodo.json file in the repository,
    # we'll fetch it here, or prompt the user to supply metadata via an email notification.
    
    # Format the raw url from the release payload
    zenodo_json_path = payload["release"]["html_url"]
    zenodo_json_path = zenodo_json_path.replace("github.com", "raw.github.com")
    zenodo_json_path = zenodo_json_path.replace("releases/tag/", '')
    zenodo_json_path += "/.zenodo.json"
    
    # Get the zenodo.json file
    r = requests.get(zenodo_json_path)
    if r.status_code is 200:
        
        zenodo_metadata = { "metadata": json.loads(r.text) }
        r = requests.put(
            "%(api)s/deposit/depositions/%(deposition_id)s?apikey=%(api_key)s" \
            % {"api": zenodo_api, "deposition_id": deposition_id, "api_key": api_key},
            data=json.dumps(zenodo_metadata),
            headers=headers,
            verify=False
        )
    
    # TODO: Handle other status codes
    else:
        # Looks like there is no zenodo.json file in the repository
        # TODO: Notify user via email to offer needed metadata before Zenodo
        # issues a DOI
        
        # TODO: Query the user based on the OAuth token, get the email address and use in send_mail
        email = User.query.filter_by(id = token).first().email
        send_email(
            CFG_SITE_ADMIN_EMAIL,
            email,
            subject="Metadata Needed For Deposition",
            content=render_template_to_string(
                "github/email_zenodo_json.html"
            )
        )
    
    # Download the archive
    release = payload["release"]
    repository = payload["repository"]
    repository_name = repository["name"]
    
    archive_url = release["zipball_url"]
    archive_name = "%(repo_name)s-%(tag_name)s.zip" % {"repo_name": repository["name"], "tag_name": release["tag_name"]}
    
    r = requests.get(archive_url, stream=True)
    if r.status_code is 200:
        with open(archive_name, 'wb') as fd:
            for chunk in r.iter_content(256):
                fd.write(chunk)
    
    # Append the file to the deposition
    data = {'filename': archive_name}
    files = {'file': open(archive_name, 'rb')}
    r = requests.post(
        "%(api)s/deposit/depositions/%(deposition_id)s/files?apikey=%(api_key)s" % \
        {"api": zenodo_api, "deposition_id": deposition_id, "api_key": api_key},
        data=data,
        files=files,
        verify=False
    )
    if r.status_code is not 201:
        # TODO: Write email stating that upload of file has failed.
        return json.dumps({"error": "file was not added to deposition"})
    
    # Publish the deposition!
    r = requests.post(
        "%(api)s/deposit/depositions/%(deposition_id)s/actions/publish?apikey=%(api_key)s" % \
        {"api": zenodo_api, "deposition_id": deposition_id, "api_key": api_key},
        verify=False
    )
    
    # Add to extra_data
    user = OAuthTokens.query.filter_by( user_id = token ).filter_by( client_id = remote.consumer_key ).first()
    user.extra_data["repos"][repository_name]["DOI"] = r.json()["doi"]
    user.extra_data["repos"][repository_name]["modified"] = r.json()["modified"]
    user.extra_data.update()
    db.session.commit()
    
    if r.status_code is 202:
        return json.dumps({"state": "deposition added successfully"})
    
    return json.dumps({"state": "deposition not published"})


@remote.tokengetter
def get_oauth_token():
    return session.get('github_token')
    