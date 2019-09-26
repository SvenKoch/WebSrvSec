import re

import bson
import jsons
import pymongo
from bson import ObjectId
from flask import Flask, render_template, request, abort, redirect

from results import SuccessResult, ErrorResult
from scanner import analyze
from scorer import Scorer

DATABASE_NAME = 'websrvsec'
COLLECTION_NAME = 'results'

app = Flask(__name__)
collection = pymongo.MongoClient().get_database(name=DATABASE_NAME).get_collection(name=COLLECTION_NAME)


def save_results(res):
    r = collection.insert_one(jsons.dump(res))
    return str(r.inserted_id)


def load_results(results_id):
    doc = collection.find_one({'_id': ObjectId(results_id)})
    return jsons.load(doc, SuccessResult)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    site = request.form['address']
    site = re.sub(r'^https?://', '', site)
    rescan = request.form['rescan']
    if rescan == '1' or not collection.find_one({'site': site}):
        res = analyze(site)
        if isinstance(res, ErrorResult):
            return render_template('error.html', error=res.error_msg)
        results_id = save_results(res)
        return redirect(f'/results/{results_id}')
    else:
        return redirect(f'/formerScans?q={site}')


@app.route('/formerScans')
def former_scans():
    site = request.args.get('q', default='')
    if not site:
        return render_template('formerScans.html', site=site, formerScans=[])
    docs = collection.find({'site': site}, limit=20)
    scans = []
    for doc in docs:
        res = jsons.load(doc, SuccessResult)
        score = Scorer(res).total_score()
        scans.append((doc, score))
    return render_template('formerScans.html', site=site, former_scans=scans)


@app.route('/results/<string:results_id>')
def results(results_id, res=None):
    if not res:
        try:
            res = load_results(results_id)
        except bson.errors.InvalidId:
            abort(404)
    scorer = Scorer(res)
    scores = {
        'total_score': scorer.total_score(),
        'cross_domain_existence_score': scorer.cross_domain_existence_score(),
        'sri_score': scorer.sri_score(),
        'mixed_content_score': scorer.mixed_content_score(),
        'up_to_date_server_software_score': scorer.up_to_date_server_software_score(),
        'up_to_date_third_party_lib_score': scorer.up_to_date_third_party_lib_score(),
        'cache_control_score': scorer.cache_control_score(),
        'referrer_policy_score': scorer.referrer_policy_score(),
        'csrf_score': scorer.csrf_score(),
        'csp_score': scorer.csp_score(),
        'cors_score': scorer.cors_score(),
        'cors_policy_score': scorer.cors_policy_score(),
        'cookie_security_score': scorer.cookie_security_score(),
        'expect_ct_score': scorer.expect_ct_score(),
        'x_download_options_score': scorer.x_download_options_score(),
        'x_frame_options_score': scorer.x_frame_options_score(),
        'x_xss_protection_score': scorer.x_xss_protection_score(),
        'x_content_type_options_score': scorer.x_content_type_options_score(),
        'hpkp_score': scorer.hpkp_score(),
        'hsts_score': scorer.hsts_score(),
        'tls_score': scorer.tls_score(),
        'http_redirection_score': scorer.http_redirection_score()
    }
    return render_template('results.html', results=res, scores=scores)


if __name__ == "__main__":
    app.run(debug=True)
