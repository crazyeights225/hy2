#!/usr/bin/env python3

#--------------------------------------
# File: translate.py
#
# Purpose: Translates properties written in our dsl to json
#--------------------------------------

import os
import json

INIT = 0
ACTION = 1
ATTRIBUTES = 2
CONDITION = 3
NEXT = 4
WHERE = 5
END = 6

stateToStr = ["INIT", "ACTION", "ATTRIBUTES", "CONDITION", "NEXT", "WHERE", "END"]

def dbg_printCurrentState(s):
    return stateToStr[s]

STATES = [
    INIT, ACTION, ATTRIBUTES, CONDITION, NEXT, WHERE, END
]

op_encoding = {
    "==": "eq",
    "!=": "neq",
    "<=": "lte",
    "<": "lt",
    ">": "gt",
    ">=": "gte"
}

def convert_condition(ls, op, rs):
    if op in ['AND', 'OR']:
        cop = op.lower()
        cond = {cop: [ls, rs]}
        return cond
    else:
        if op in op_encoding:
            op = op_encoding[op]
        cond = {'ls': ls, 'op': op, 'rs': rs}
        return cond

def parse_condition(statement):
    stack = []
    conditions = []
    i = 0
    stmt = statement.split(" ")
    while True:
        token = stmt[i]
        if token == '':
            if i == len(stmt) - 1:
                break
            i += 1
            continue
        elif token[0] == '(':
            stack = ['('] + stack
            stmt[i] = stmt[i][1:]
        elif token[-1] == ')' and len(token) > 1:
            stack = [token[:-1]] + stack
            stmt[i] = token[-1:]
        elif token in ['AND', 'OR']:
            if len(stack) >= 3:
                rs = stack.pop(0)
                op = stack.pop(0)
                ls = stack.pop(0)
                cond = convert_condition(ls, op, rs)
                stack = [cond] + stack
            stack = [token] + stack
            i += 1
        elif token[0] == ')':
            haltLoop = False
            while not haltLoop:
                rs =  stack.pop(0)
                op = stack.pop(0)
                ls = stack.pop(0)
                if stack[0] == '(':
                    stack.pop(0)
                    haltLoop = True
                cond = convert_condition(ls, op, rs)
                stack = [cond] + stack
            i += 1
        else:
            stack = [token] + stack
            i += 1
        if i == len(stmt):
            break
    if len(stack) > 2:
        ls = stack[2]
        op = stack[1]
        rs = stack[0]
        if op in ['AND', 'OR']:
            cop = op.lower()
            cond = {cop: [ls, rs]}
            conditions.append(cond)
        else:
            if op in op_encoding:
                op = op_encoding[op]
            cond = {'ls': ls, 'op': op, 'rs': rs}
            conditions.append(cond)
    elif len(stack) == 1:
        conditions.append(stack[0])
    
    return conditions

def parseAntiStatement(stmt):
    stack = []

    i = 0
    stmt = stmt.split(' ')
    while True:
        token = stmt[i]
        if token == '':
            if i == len(stmt) - 1:
                break
            i += 1
            continue
        elif token[0] == '(':
            stack = ['('] + stack
            stmt[i] = stmt[i][1:]
        elif token[0] == ')':
            rs = stack.pop(0)
            op = stack.pop(0)
            ls = stack.pop(0)
            assert stack[0] == '('
            stack.pop(0)
            if op in ['AND', 'OR']:
                cop = op.lower()
                cond = {'ls': ls, 'op': cop, 'rs': rs}
                stack = [cond] + stack
            else:
                raise Exception("Syntax Error: expected one of AND, OR")
        else:
            stack = [token] + stack
            i += 1
        if i >= len(stmt):
            break

    if len(stack) > 2:
        ls = stack[2]
        op = stack[1]
        rs = stack[0]
        if op in ['AND', 'OR']:
            cop = op.lower()
            return {'ls': ls, 'op': cop, 'rs': rs}
        else:
            raise Exception('Syntax ERROR: expected one of AND, OR')
    else:
        return stack[0]

def convert_property(property_name):
    if not os.path.exists(property_name):
        property_file = os.path.join("dsl", property_name)
    else:
        property_file = property_name
    
    f =  open(property_file, 'r')
    data = f.read()
    f.close()
    property_json = translate_property(data)
    if property_json == None:
        return
    json_property_file = os.path.join('json', os.path.basename(property_file).split('.')[0] + '.json')
    with open(json_property_file, 'w') as f:
        json.dump(property_json, f, indent=2)

def translate_property(data):
    lines = data.split('\n')
    property_model = []
    current_state = INIT
    i = 0
    rule = {}
    rule['name'] = ''
    rule['severity'] = ''
    rule['sequences'] = []
    current_prop_anti = {}
    current_event = {}
    while True:
        l =  lines[i]
        if l == '---' and current_state != INIT:
            current_state = INIT
            if property_model != []:
                rule['sequences'] += [{'model': property_model}]
                if current_prop_anti != {}:
                    rule['sequences'][-1]['anti_expr'] = current_prop_anti
                    current_prop_anti = {}
                property_model = []
        elif current_state == INIT:
            if 'Name:' in l:
                rule['name'] = l.split('Name:')[1].strip()
            elif 'Severity:' in l:
                rule['severity'] = l.split('Severity:')[1].strip()
            elif l == '---':
                current_state = ACTION
            i += 1
        elif current_state == ACTION:    
            if l == '' and 'action' in current_event:
                property_model += [current_event]
                current_event = {}
                current_state = ACTION
                i += 1
            elif l == '':
                print('Syntax Error: Expected Action!')
                return
            elif l[:4] == 'NOT ':
                l = l[4:]
                current_event['type'] = 'anti'
                if 'as' in l:
                    l = l.split('as')
                    current_event['label'] = l[1].strip()
                    current_event['action'] = l[0].strip()
                else:
                    current_event['action'] = l.strip()
                current_state = ATTRIBUTES
                i += 1
            else:
                current_event['action'] = l
                current_state = ATTRIBUTES
                i += 1
        elif current_state == ATTRIBUTES:
            if l == '':
                property_model += [current_event]
                current_event = {}
                current_state = ACTION
            elif l[:4] != "with":
                print('Syntax Error: with expected at the beginning of attribute line')
            else:
                attributes = {}
                l = l[4:]
                pairs = l.split(",")
                for p in pairs:
                    a = p.split('=')
                    k = a[0].strip()
                    v = a[1].strip()
                    attributes[v] = k
                current_event['attributes'] = attributes
                current_state = CONDITION
            i += 1
        elif current_state == CONDITION:
            if l == '':
                property_model += [current_event]
                current_event = {}
                current_state = NEXT
            elif l[:5] != 'where':
                print('Syntax Error: where expected at the beginning of the condition line')
                return
            else:
                l = l[5:]
                conditions = parse_condition(l)
                current_event['cond'] = conditions
                property_model += [current_event]
                current_event = {}
                current_state = NEXT
                i+=1
        elif current_state == WHERE:
            if l == '':
                i += 1
            elif l == '---':
                current_state = NEXT
            elif 'WHERE' in l:
                l0 = l.split('WHERE')[1].lstrip()
                astmt = parseAntiStatement(l0)
                current_prop_anti = astmt
                i += 1
                current_state = NEXT
            else:
                raise Exception("Could not parse statement!")
        
        elif current_state == NEXT:
            if l == '':
                i += 1
            elif l == '---':
                current_state = END
            elif l[:2] == "if":
                l0 = l[2:].lstrip()
                cond = parse_condition(l0)
                property_model[-1]['vuln'] = cond
                i+=1
            elif 'WHERE' in l:
                current_state = WHERE
            else:
                current_state = ACTION
        
        elif current_state == END:
            pass
        if i == len(lines):
            break

    return rule

import argparse
parser = argparse.ArgumentParser()
parser.add_argument('-p', '--property', action='store', type=str, help='property file to parse')

args = vars(parser.parse_args())

if __name__ == "__main__":
    property_file = args['property']
    print(property_file)
    convert_property(property_file)