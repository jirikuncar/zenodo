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

import requests
from flask import Blueprint, render_template, redirect, url_for, session, request, jsonify
from flask.ext.login import current_user

from invenio.ext.sqlalchemy import db
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
    
    return render_template("github/index.html", **context)

@blueprint.route('/connect')
def connect():
    return remote.authorize(
        callback = url_for('.connected', _external = True)
    )

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
    print "TOKEN", resp['access_token']
    
    session['github_token'] = (token, '')
    
    # Check if the user has previously created a GitHub OAuth token
    user = OAuthTokens.query.filter_by(user_id = current_user.get_id()).filter_by(client_id = remote.consumer_key).first()
    if user is None:
        
        # Get user data
        resp = remote.get('user')
        github_login = resp.data['login']
        
        # Get repo data
        resp = remote.get("users/%(username)s/repos" % {"username": github_login})
        repos = resp.data
        def get_repo_name(repo): return repo["name"]
        repos = map(get_repo_name, repos)
        
        # Put user's GitHub info in database
        o = OAuthTokens(
            client_id = remote.consumer_key,
            user_id = current_user.get_id(),
            access_token = token,
            extra_data = {"login": github_login, "repos": repos}
        )
        db.session.add(o)
    else:
        # User has previously connected to the GitHub client. Update the token.
        user.access_token = token
        github_login = user.extra_data['login']
    
    db.session.commit()
    
    # Store the GitHub user on session
    session["github_login"] = github_login
    
    return redirect( url_for('.index') )

@blueprint.route('/create-github-hook/<repo>', methods=["POST"])
def create_github_hook(repo):
    
    # TODO: Check that we have github_login on session
    
    endpoint = "repos/%(owner)s/%(repo)s/hooks" % {"owner": session["github_login"], "repo": repo}
    print endpoint
    data = {
        "name": "web",
        "config": {
            "url": "http://requestb.in/1gkugi21"
        },
        "events": ["release"],
        "active": True
    }
    
    resp = remote.post(endpoint, format='json', data=data)
    return json.dumps(resp.data)

@remote.tokengetter
def get_oauth_token():
    return session.get('github_token')
    