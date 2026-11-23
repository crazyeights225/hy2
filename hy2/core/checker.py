#--------------------------------------
# File: checker.py
#
# Purpose: Loads rules and program model and runs the checker
#--------------------------------------
import os
import json
import hy2.core.utils as utils
import pickle
from colorama import Fore
import hy2.core.results_post_processor as rpp
from hy2.core.check_helpers import load_property_model, Match, Candidate


import hy2.core.checker_single as checker_single
import hy2.core.checker_multi as checker_multi

class Model:
    pass

def load_aliases(properties_dir):
    libs_file = os.path.join(properties_dir, 'json', 'lib.json')
    f = open(libs_file, 'r')
    return json.load(f)

def load_property(properties_dir, property, aliases, sem_info):
    f = open(os.path.join(properties_dir, 'json', property), 'r')
    data = json.load(f)
    seq = data['sequences']
    name = data['name']
    severity = data['severity']
    models = [load_property_model(z, name, severity, aliases, sem_info) for z in seq]
    return models

def load_properties(properties_dir, properties, aliases, target_dir):
    property_models = []
    sem_info = utils.get_semantic_info(target_dir)
    for p in properties:
        property_models += load_property(properties_dir, p, aliases, sem_info)
    return property_models


def initialize_check(GLOB_CONF, target, properties):
    # load properties
    aliases = load_aliases(GLOB_CONF.property_dir)
    property_models = load_properties(GLOB_CONF.property_dir, 
    properties, aliases, os.path.join(GLOB_CONF.target_path, target))

    # load model:
    f = open(os.path.join(GLOB_CONF.target_path, target, "model.trace"), "rb")
    model = pickle.load(f)
    f.close()

    f1 = open(os.path.join(GLOB_CONF.target_path, target, "model.labels"), "rb")
    labels = pickle.load(f1)
    f1.close()
    
    if GLOB_CONF.enable_multithread_analysis:
        f = open(os.path.join(GLOB_CONF.target_path, target, "threadmodel.bin"), "rb")
        thread_model = pickle.load(f)
        f.close()

        checker_multi.do_check(GLOB_CONF, target, property_models, aliases, thread_model, model, labels)
    else:
        checker_single.do_check(GLOB_CONF, target, property_models, aliases, model, labels)

    rpp.post_process_results(GLOB_CONF, target, labels)