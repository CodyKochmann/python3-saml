
from flask import (Flask, request, render_template, redirect, session, make_response)
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from urlparse import urlparse
import os

get_self_url = OneLogin_Saml2_Utils.get_self_url


''' example of a python saml flask server '''


app = Flask(__name__)
app.config['SECRET_KEY'] = 'onelogindemopytoolkit'
app.config['SAML_PATH'] = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'saml')


def init_saml_auth(req):
    return OneLogin_Saml2_Auth(req, custom_base_path=app.config['SAML_PATH'])

def prepare_flask_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': urlparse(request.url).port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }

@app.route('/', methods=['GET', 'POST'])
def index():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    successful_log_out = False

    if 'sso' in request.args:
        return redirect(auth.login())

    elif 'sso2' in request.args:
        return redirect(
            auth.login(
                '{}attrs/'.format(request.host_url)
            )
        )

    elif 'slo' in request.args:
        return redirect(
            auth.logout(
                name_id=session.get('samlNameId', None),
                session_index=session.get('samlSessionIndex', None)
            )
        )

    elif 'acs' in request.args:
        auth.process_response()
        if not auth.get_errors():
            session.update(
                'samlUserdata': auth.get_attributes(),
                'samlNameId': auth.get_nameid(),
                'samlSessionIndex': auth.get_session_index()
            )
            if 'RelayState' in request.form and get_self_url(req) != request.form['RelayState']:
                return redirect(auth.redirect_to(request.form['RelayState']))

    elif 'sls' in request.args:
        url = auth.process_slo(delete_session_cb=session.clear)
        if not auth.get_errors():
            if url is None:
                successful_log_out = True
            else:
                return redirect(url)

    return render_template(
        'index.html',
        errors=[],
        not_auth_warn=(not auth.is_authenticated()),
        successful_log_out=successful_log_out,
        attributes=session.get('samlUserdata', {}).items(),
        paint_logout=('samlUserdata' in session)
    )


@app.route('/attrs/')
def attrs():
    return render_template(
        'attrs.html',
        paint_logout='samlUserdata' in session,
        attributes=session.get('samlUserdata', {}).items()
    )


@app.route('/metadata/')
def metadata():
    settings = init_saml_auth(
        prepare_flask_request(request)
    ).get_settings()

    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors):
        return make_response(errors.join(', '), 500)
    else:
        resp = make_response(metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
        return resp


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)
