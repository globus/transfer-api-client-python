#!/usr/bin/env python

# Copyright 2010 University of Chicago
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Demonstrate API calls.

Example run using standard globus toolkit certificate locations:

python example.py USERNAME -k ~/.globus/userkey.pem -c ~/.globus/usercert.pem
"""
from __future__ import print_function
import time
from datetime import datetime, timedelta

from globusonline.transfer.api_client import Transfer, create_client_from_args


# TransferAPIClient instance.
api = None


def tutorial():
    """
    Do a bunch of API calls and display the results. Does a small transfer
    between tutorial endpoints, but otherwise does not modify user data.

    Uses module global API client instance.
    """
    # See what is in the account before we make any submissions.
    print("=== Before tutorial ===")
    display_tasksummary(); print("")
    display_task_list(); print("")
    display_endpoint_list(); print("")

    # auto activate the endpoint, and display before/after.
    display_activation("go#ep1")
    display_activation("go#ep2")

    print("=== Before transfer ===")
    display_ls("go#ep1"); print("")
    display_ls("go#ep2"); print("")

    # submit a transfer
    code, message, data = api.transfer_submission_id()
    submission_id = data["value"]
    deadline = datetime.utcnow() + timedelta(minutes=10)
    t = Transfer(submission_id, "go#ep1", "go#ep2", deadline)
    t.add_item("/~/.bashrc", "/~/api-example-bashrc-copy")
    code, reason, data = api.transfer(t)
    task_id = data["task_id"]

    # see the new transfer show up
    print("=== After submit ===")
    display_tasksummary(); print("")
    display_task(task_id, False); print("")

    # wait for the task to complete, and see the tasks and
    # endpoint ls change
    status = wait_for_task(task_id)

    if status is None:
        # Task didn't complete before the timeout.
        # Since the example transfers a single small file and the
        # timeout is 2 mintues, this shouldn't happen unless one of the
        # endpoints is having problems or the user already has a bunch
        # of other active tasks (there is a limit to the
        # number of concurrent active tasks a user can have).
        print("WARNING: task did not complete before timeout!")
    else:
        print("Task %s complete with status %s" % (task_id, status))
        print("=== After completion ===")
        display_tasksummary(); print("")
        display_task(task_id); print("")
        display_ls("go#ep2"); print("")


def display_activation(endpoint_name):
    print("=== Endpoint pre-activation ===")
    display_endpoint(endpoint_name)
    print("")
    code, reason, result = api.endpoint_autoactivate(endpoint_name,
                                                     if_expires_in=600)
    if result["code"].startswith("AutoActivationFailed"):
        print("Auto activation failed, ls and transfers will likely fail!")
    print("result: %s (%s)" % (result["code"], result["message"]))
    print("=== Endpoint post-activation ===")
    display_endpoint(endpoint_name)
    print("")


def display_tasksummary():
    code, reason, data = api.tasksummary()
    print("Task Summary for %s:" % api.username)
    for k, v in data.iteritems():
        if k == "DATA_TYPE":
            continue
        print("%3d %s" % (int(v), k.upper().ljust(9)))


def display_task_list(max_age=None):
    """
    @param max_age: only show tasks requested at or after now - max_age.
    @type max_age: timedelta
    """
    kwargs = {}
    if max_age:
        min_request_time = datetime.utcnow() - max_age
        # filter on request_time starting at min_request_time, with no
        # upper limit on request_time.
        kwargs["request_time"] = "%s," % min_request_time

    code, reason, task_list = api.task_list(**kwargs)
    print("task_list for %s:" % api.username)
    for task in task_list["DATA"]:
        print("Task %s:" % task["task_id"])
        _print_task(task)


def _print_task(data, indent_level=0):
    indent = " " * indent_level
    indent += " " * 2
    for k, v in data.iteritems():
        if k in ("DATA_TYPE", "LINKS"):
            continue
        print(indent + "%s: %s" % (k, v))


def display_task(task_id, show_successful_transfers=True):
    code, reason, data = api.task(task_id)
    print("Task %s:" % task_id)
    _print_task(data, 0)

    if show_successful_transfers:
        code, reason, data = api.task_successful_transfers(task_id)
        transfer_list = data["DATA"]
        print("Successful Transfers (src -> dst)")
        for t in transfer_list:
            print(" %s -> %s" % (t[u'source_path'],
                                 t[u'destination_path']))


def wait_for_task(task_id, timeout=120, poll_interval=30):
    """
    Wait for a task to complete within @timeout seconds, polling
    every @poll_interval seconds. If the task completed in the timeout,
    return the status ("SUCCEEDED" or "FAILED"). If it did not complete,
    returns None. Caller is responsible for cancelling incomplete task
    as appropriate.
    """
    assert timeout % poll_interval == 0, \
        "timeout must be multiple of poll_interval"
    timeout_left = timeout
    while timeout_left >= 0:
        code, reason, data = api.task(task_id, fields="status")
        status = data["status"]
        if status in ("SUCCEEDED", "FAILED"):
            return status
        if timeout_left > 0:
            time.sleep(poll_interval)
        timeout_left -= poll_interval

    return None


def display_endpoint_list():
    code, reason, endpoint_list = api.endpoint_list(limit=100)
    print("Found %d endpoints for user %s:" \
          % (endpoint_list["length"], api.username))
    for ep in endpoint_list["DATA"]:
        _print_endpoint(ep)


def display_endpoint(endpoint_name):
    code, reason, data = api.endpoint(endpoint_name)
    _print_endpoint(data)


def _print_endpoint(ep):
    name = ep["canonical_name"]
    print(name)
    if ep["activated"]:
        print("  activated (expires: %s)" % ep["expire_time"])
    else:
        print("  not activated")
    if ep["public"]:
        print("  public")
    else:
        print("  not public")
    if ep["myproxy_server"]:
        print("  default myproxy server: %s" % ep["myproxy_server"])
    else:
        print("  no default myproxy server")
    servers = ep.get("DATA", ())
    print("  servers:")
    for s in servers:
        uri = s["uri"]
        if not uri:
            uri = "GC endpoint, no uri available"
        print("    " + uri,)
        if s["subject"]:
            print(" (%s)" % s["subject"])
        else:
            print("")


def display_ls(endpoint_name, path=""):
    code, reason, data = api.endpoint_ls(endpoint_name, path)
    # The "path" field contains the canonical path from the GridFTP server. For
    # aboslute paths this will be the same as the requested path, but in some
    # cases it will be mapped. Also an empty path can be passed
    # and will be mapped to the user's default directory (typically
    # their home directory) by the Transfer API.
    path = data["path"]
    print("Contents of %s on %s:" % (path, endpoint_name))
    headers = "name, type, permissions, size, user, group, last_modified"
    headers_list = headers.split(", ")
    print(headers)
    for file_or_dir in data["DATA"]:
        print(", ".join([unicode(file_or_dir[field])
                         for field in headers_list]))


if __name__ == '__main__':
    api, _ = create_client_from_args()
    tutorial()
