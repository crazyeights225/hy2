#--------------------------------------
# File: app.py
#
# Purpose: endpoints for web application
#--------------------------------------
from flask import Flask, render_template, request, jsonify, redirect, flash, abort
import backend
import traceback
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'

@app.context_processor
def inject_nav():
    # Lets base.html highlight the current section
    return {'nav_active': request.path.strip('/').split('/')[0] or 'home'}

@app.route('/')
def index():
    data = backend.get_index_stats()
    return render_template('index.html', data=data)

@app.route('/targets')
def targets():
    return render_template('targets.html', title="Targets")

@app.route('/api/targets')
def api_targets():
    data = backend.get_target_list()
    return jsonify({'data': data})

@app.route('/queue')
def get_queue():
    data = backend.get_queue()
    return render_template('queue.html', data=data, title='Queue')

@app.route('/result')
def get_result():
    name = request.args.get('name')
    vid = request.args.get('id')
    data = backend.get_result_by_id(name, vid, request.args.get('filter'))
    if data is None:
        abort(404)
    return render_template('result.html', data=data, title=f'{data["property"]} - {name}')

@app.route('/properties')
def properties():
    properties = backend.get_property_list()
    return render_template('properties.html', data=properties, title='Properties')

@app.route('/target')
def target_profile():
    name = request.args.get('name')
    data = backend.get_target_profile(name)
    title = f'Profile - {name}'
    return render_template('profile.html', test_case=data, title=title)

@app.route('/new')
def new_target():
    return render_template('new_target.html', title = "New")

@app.route('/settings')
def settings_page():
    data = backend.get_settings()
    return render_template('settings.html', data=data, title='Settings')

@app.route('/config')
def config_target():
    name = request.args.get('name')
    config_data, input_exs = backend.get_target_config(name)
    data = {'name': name, 'config': config_data, 'test_cases': input_exs}
    return render_template('config.html', target=data, title=f'Config - {name}')

@app.route('/log')
def view_result_log():
    name = request.args.get('name')
    id = request.args.get('id')
    data = {'target': name, 'vid': id}
    data.update(backend.get_result_source(name, id))
    return render_template('log.html', data=data, title=f'Source - {name}')

@app.route('/query')
def query_target():
    target = request.args.get('name')
    tid = None
    bid = None
    query = None
    if 'tid' in request.args:
        tid = request.args.get('tid')
    if 'bid' in request.args:
        bid = request.args.get('bid')
    if 'query' in request.args:
        query = request.args.get('query')
    data = backend.query_target(target, tid, bid, query)
    return render_template('query.html', data=data, title=f'Query - {target}')

@app.route('/add', methods=['POST'])
def add_input_example():
    target = request.form.get('target')
    cmd = request.form.get('cmd')
    rc = backend.add_input_example(target, cmd)
    if rc == 0:
        flash('Success!')
    else:
        flash('Error parsing commands!')
    return redirect(f'/config?name={target}')

@app.route('/api/property')
def api_property():
    name = request.args.get('id')
    data = backend.read_property(name)
    return jsonify({'data': data})

@app.route('/api/target/update', methods=['POST'])
def api_target_config():
    data = request.form
    backend.update_target_profile(data)
    return redirect(f'/config?name={data["name"]}')

@app.route('/api/target/new', methods=["POST"])
def api_target_new():
    data = request.form
    backend.create_target_profile(data)
    flash('Success!')
    return redirect('/new')

@app.route('/api/target/properties', methods=['POST'])
def api_target_properties():
    name = request.form.get('target')
    backend.update_selected_properties(name, request.form)
    return redirect(f'/config?name={name}')

@app.route('/api/queue/update', methods=['POST'])
def api_queue_update():
    data = request.form.get('queue')
    backend.update_queue(data)
    return redirect('/queue')

@app.route('/api/testcase')
def api_testcase():
    name = request.args.get('name')
    tid = request.args.get('id')
    data = backend.get_input_example(name, tid)
    return jsonify({'data': data})

@app.route('/api/queue/push')
def api_queue_push():
    tid = request.args.get('id')
    target = request.args.get('name')
    data = {'target': target, 'task': tid}
    status = backend.add_to_queue(data)
    return jsonify(status)

@app.route('/api/queue/push_target')
def api_queue_push_target():
    target = request.args.get('name')
    tasks = request.args.get('tasks')
    if tasks is not None:
        tasks = [t.strip() for t in tasks.split(',') if t.strip() != '']
    status = backend.queue_target_tasks(target, tasks)
    return jsonify(status)

@app.route('/api/settings', methods=['POST'])
def api_settings():
    backend.update_settings(request.form)
    return redirect('/settings')

@app.route('/api/queue/clear')
def api_queue_clear():
    backend.clear_queue()
    return jsonify({'status': 'success'})

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500
