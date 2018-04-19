
from flask import (Flask, request, render_template, redirect, session, make_response)
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from urlparse import urlparse
import os

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
    errors = []
    success_slo = False
    attributes = False
    paint_logout = False

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
        if len(auth.get_errors()) == 0:
            session['samlUserdata'] = auth.get_attributes()
            session['samlNameId'] = auth.get_nameid()
            session['samlSessionIndex'] = auth.get_session_index()
            self_url = OneLogin_Saml2_Utils.get_self_url(req)
            if 'RelayState' in request.form and self_url != request.form['RelayState']:
                return redirect(auth.redirect_to(request.form['RelayState']))
    elif 'sls' in request.args:
        url = auth.process_slo(delete_session_cb=session.clear)
        if len(auth.get_errors()) == 0:
            if url is None:
                success_slo = True
            else:
                return redirect(url)

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items() # otherwise this is False?

    return render_template(
        'index.html',
        errors=errors,
        not_auth_warn=(not auth.is_authenticated()),
        success_slo=success_slo,
        attributes=attributes,
        paint_logout=paint_logout
    )


@app.route('/attrs/')
def attrs():
    return render_template(
        'attrs.html',
        paint_logout='samlUserdata' in session,
        attributes=session['samlUserdata'].items() if 'samlUserdata' in session and len(session['samlUserdata']) > 0 else False
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
