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
GitHub Settings Blueprint
"""

from __future__ import absolute_import

from flask import Blueprint, render_template
from flask.ext.login import login_required
from flask.ext.breadcrumbs import register_breadcrumb
from flask.ext.menu import register_menu

from invenio.base.i18n import _
from invenio.ext.sslify import ssl_required


blueprint = Blueprint(
    'zenodo_github_settings',
    __name__,
    url_prefix="/account/settings/github",
    static_folder="../static",
    template_folder="../templates",
)


@blueprint.route("/")
@ssl_required
@login_required
@register_menu(
    blueprint, 'settings.github',
    _('<i class="fa fa-github fa-fw"></i> GitHub')
)
@register_breadcrumb(blueprint, '.index', _('GitHub'))
def index():
    return render_template("github/index.html")
