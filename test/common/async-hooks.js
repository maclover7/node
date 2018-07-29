'use strict';
// Flags: --expose-gc

const common = require('./');
const assert = require('assert');
const async_hooks = require('async_hooks');
const util = require('util');
const print = process._rawDebug;

if (typeof global.gc === 'function') {
  (function exity(cntr) {
    process.once('beforeExit', () => {
      global.gc();
      if (cntr < 4) setImmediate(() => exity(cntr + 1));
    });
  })(0);
}

function noop() {}

class ActivityCollector {
  constructor(start, {
    allowNoInit = false,
    oninit,
    onbefore,
    onafter,
    ondestroy,
    onpromiseResolve,
    logid = null,
    logtype = null
  } = {}) {
    this._start = start;
    this._allowNoInit = allowNoInit;
    this._activities = new Map();
    this._logid = logid;
    this._logtype = logtype;

    // Register event handlers if provided
    this.oninit = typeof oninit === 'function' ? oninit : noop;
    this.onbefore = typeof onbefore === 'function' ? onbefore : noop;
    this.onafter = typeof onafter === 'function' ? onafter : noop;
    this.ondestroy = typeof ondestroy === 'function' ? ondestroy : noop;
    this.onpromiseResolve = typeof onpromiseResolve === 'function' ?
      onpromiseResolve : noop;

    // Create the hook with which we'll collect activity data
    this._asyncHook = async_hooks.createHook({
      init: this._init.bind(this),
      before: this._before.bind(this),
      after: this._after.bind(this),
      destroy: this._destroy.bind(this),
      promiseResolve: this._promiseResolve.bind(this)
    });
  }

  enable() {
    this._asyncHook.enable();
  }

  disable() {
    this._asyncHook.disable();
  }

  sanityCheck(types) {
    if (types != null && !Array.isArray(types)) types = [ types ];

    function activityString(a) {
      return util.inspect(a, false, 5, true);
    }

    const violations = [];
    let tempActivityString;

    function v(msg) { violations.push(msg); }
    for (const a of this._activities.values()) {
      tempActivityString = activityString(a);
      if (types != null && !types.includes(a.type)) continue;

      if (a.init && a.init.length > 1) {
        v(`Activity inited twice\n${tempActivityString}` +
          '\nExpected "init" to be called at most once');
      }
      if (a.destroy && a.destroy.length > 1) {
        v(`Activity destroyed twice\n${tempActivityString}` +
          '\nExpected "destroy" to be called at most once');
      }
      if (a.before && a.after) {
        if (a.before.length < a.after.length) {
          v('Activity called "after" without calling "before"\n' +
            `${tempActivityString}` +
            '\nExpected no "after" call without a "before"');
        }
        if (a.before.some((x, idx) => x > a.after[idx])) {
          v('Activity had an instance where "after" ' +
            'was invoked before "before"\n' +
            `${tempActivityString}` +
            '\nExpected "after" to be called after "before"');
        }
      }
      if (a.before && a.destroy) {
        if (a.before.some((x, idx) => x > a.destroy[idx])) {
          v('Activity had an instance where "destroy" ' +
            'was invoked before "before"\n' +
            `${tempActivityString}` +
            '\nExpected "destroy" to be called after "before"');
        }
      }
      if (a.after && a.destroy) {
        if (a.after.some((x, idx) => x > a.destroy[idx])) {
          v('Activity had an instance where "destroy" ' +
            'was invoked before "after"\n' +
            `${tempActivityString}` +
            '\nExpected "destroy" to be called after "after"');
        }
      }
      if (!a.handleIsObject) {
        v(`No resource object\n${tempActivityString}` +
          '\nExpected "init" to be called with a resource object');
      }
    }
    if (violations.length) {
      console.error(violations.join('\n\n') + '\n');
      assert.fail(violations.length, 0,
                  `${violations.length} failed sanity checks`);
    }
  }

  inspect(opts = {}) {
    if (typeof opts === 'string') opts = { types: opts };
    const { types = null, depth = 5, stage = null } = opts;
    const activities = types == null ?
      Array.from(this._activities.values()) :
      this.activitiesOfTypes(types);

    if (stage != null) console.log(`\n${stage}`);
    console.log(util.inspect(activities, false, depth, true));
  }

  activitiesOfTypes(types) {
    if (!Array.isArray(types)) types = [ types ];
    return this.activities.filter((x) => types.includes(x.type));
  }

  get activities() {
    return Array.from(this._activities.values());
  }

  _stamp(h, hook) {
    if (h == null) return;
    if (h[hook] == null) h[hook] = [];
    const time = process.hrtime(this._start);
    h[hook].push((time[0] * 1e9) + time[1]);
  }

  _getActivity(uid, hook) {
    const h = this._activities.get(uid);
    if (!h) {
      // If we allowed handles without init we ignore any further life time
      // events this makes sense for a few tests in which we enable some hooks
      // later
      if (this._allowNoInit) {
        const stub = { uid, type: 'Unknown', handleIsObject: true };
        this._activities.set(uid, stub);
        return stub;
      } else if (!common.isMainThread) {
        // Worker threads start main script execution inside of an AsyncWrap
        // callback, so we don't yield errors for these.
        return null;
      } else {
        const err = new Error(`Found a handle whose ${hook}` +
                              ' hook was invoked but not its init hook');
        // Don't throw if we see invocations due to an assertion in a test
        // failing since we want to list the assertion failure instead
        if (/process\._fatalException/.test(err.stack)) return null;
        throw err;
      }
    }
    return h;
  }

  _init(uid, type, triggerAsyncId, handle) {
    const activity = {
      uid,
      type,
      triggerAsyncId,
      // In some cases (e.g. Timeout) the handle is a function, thus the usual
      // `typeof handle === 'object' && handle !== null` check can't be used.
      handleIsObject: handle instanceof Object
    };
    this._stamp(activity, 'init');
    this._activities.set(uid, activity);
    this._maybeLog(uid, type, 'init');
    this.oninit(uid, type, triggerAsyncId, handle);
  }

  _before(uid) {
    const h = this._getActivity(uid, 'before');
    this._stamp(h, 'before');
    this._maybeLog(uid, h && h.type, 'before');
    this.onbefore(uid);
  }

  _after(uid) {
    const h = this._getActivity(uid, 'after');
    this._stamp(h, 'after');
    this._maybeLog(uid, h && h.type, 'after');
    this.onafter(uid);
  }

  _destroy(uid) {
    const h = this._getActivity(uid, 'destroy');
    this._stamp(h, 'destroy');
    this._maybeLog(uid, h && h.type, 'destroy');
    this.ondestroy(uid);
  }

  _promiseResolve(uid) {
    const h = this._getActivity(uid, 'promiseResolve');
    this._stamp(h, 'promiseResolve');
    this._maybeLog(uid, h && h.type, 'promiseResolve');
    this.onpromiseResolve(uid);
  }

  _maybeLog(uid, type, name) {
    if (this._logid &&
      (type == null || this._logtype == null || this._logtype === type)) {
      print(`${this._logid}.${name}.uid-${uid}`);
    }
  }
}

function initHooks({
  oninit,
  onbefore,
  onafter,
  ondestroy,
  onpromiseResolve,
  allowNoInit,
  logid,
  logtype
} = {}) {
  return new ActivityCollector(process.hrtime(), {
    oninit,
    onbefore,
    onafter,
    ondestroy,
    onpromiseResolve,
    allowNoInit,
    logid,
    logtype
  });
};

/**
 * Checks the expected invocations against the invocations that actually
 * occurred.
 *
 * @name checkInvocations
 * @function
 * @param {Object} activity including timestamps for each life time event,
 *                 i.e. init, before ...
 * @param {Object} hooks the expected life time event invocations with a count
 *                       indicating how often they should have been invoked,
 *                       i.e. `{ init: 1, before: 2, after: 2 }`
 * @param {String} stage the name of the stage in the test at which we are
 *                       checking the invocations
 */
function checkInvocations(activity, hooks, stage) {
  const stageInfo = `Checking invocations at stage "${stage}":\n   `;

  assert.ok(activity != null,
            `${stageInfo} Trying to check invocation for an activity, ` +
            'but it was empty/undefined.'
  );

  // Check that actual invocations for all hooks match the expected invocations
  [ 'init', 'before', 'after', 'destroy', 'promiseResolve' ].forEach(checkHook);

  function checkHook(k) {
    const val = hooks[k];
    // Not expected ... all good
    if (val == null) return;

    if (val === 0) {
      // Didn't expect any invocations, but it was actually invoked
      const invocations = activity[k].length;
      const msg = `${stageInfo} Called "${k}" ${invocations} time(s), ` +
                  'but expected no invocations.';
      assert(activity[k] === null && activity[k] === undefined, msg);
    } else {
      // Expected some invocations, make sure that it was invoked at all
      const msg1 = `${stageInfo} Never called "${k}", ` +
                   `but expected ${val} invocation(s).`;
      assert(activity[k] !== null && activity[k] !== undefined, msg1);

      // Now make sure that the expected count and
      // the actual invocation count match
      const msg2 = `${stageInfo}  Called "${k}" ${activity[k].length} ` +
                   `time(s), but expected ${val} invocation(s).`;
      assert.strictEqual(activity[k].length, val, msg2);
    }
  }
};

function tick(x, cb) {
  function ontick() {
    if (--x === 0) {
      if (typeof cb === 'function') cb();
    } else {
      setImmediate(ontick);
    }
  }
  setImmediate(ontick);
};

function findInGraph(graph, type, n) {
  let found = 0;
  for (let i = 0; i < graph.length; i++) {
    const node = graph[i];
    if (node.type === type) found++;
    if (found === n) return node;
  }
}

function pruneTickObjects(activities) {
  // remove one TickObject on each pass until none is left anymore
  // not super efficient, but simplest especially to handle
  // multiple TickObjects in a row
  let foundTickObject = true;

  while (foundTickObject) {
    foundTickObject = false;
    let tickObjectIdx = -1;
    for (let i = 0; i < activities.length; i++) {
      if (activities[i].type !== 'TickObject') continue;
      tickObjectIdx = i;
      break;
    }

    if (tickObjectIdx >= 0) {
      foundTickObject = true;

      // point all triggerAsyncIds that point to the tickObject
      // to its triggerAsyncId and finally remove it from the activities
      const tickObject = activities[tickObjectIdx];
      const newTriggerId = tickObject.triggerAsyncId;
      const oldTriggerId = tickObject.uid;
      activities.forEach(function repointTriggerId(x) {
        if (x.triggerAsyncId === oldTriggerId) x.triggerAsyncId = newTriggerId;
      });
      activities.splice(tickObjectIdx, 1);
    }
  }
  return activities;
}

//
// Helper to generate the input to the verifyGraph tests
//
function inspect(obj, depth) {
  console.error(util.inspect(obj, false, depth || 5, true));
}

function verifyGraph(hooks, graph) {
  pruneTickObjects(hooks);

  // map actual ids to standin ids defined in the graph
  const idtouid = {};
  const uidtoid = {};
  const typeSeen = {};
  const errors = [];

  const activities = pruneTickObjects(hooks.activities);
  activities.forEach(processActivity);

  function processActivity(x) {
    if (!typeSeen[x.type]) typeSeen[x.type] = 0;
    typeSeen[x.type]++;

    const node = findInGraph(graph, x.type, typeSeen[x.type]);
    if (node == null) return;

    idtouid[node.id] = x.uid;
    uidtoid[x.uid] = node.id;
    if (node.triggerAsyncId == null) return;

    const tid = idtouid[node.triggerAsyncId];
    if (x.triggerAsyncId === tid) return;

    errors.push({
      id: node.id,
      expectedTid: node.triggerAsyncId,
      actualTid: uidtoid[x.triggerAsyncId]
    });
  }

  if (errors.length) {
    errors.forEach((x) =>
      console.error(
        `'${x.id}' expected to be triggered by '${x.expectedTid}', ` +
        `but was triggered by '${x.actualTid}' instead.`
      )
    );
  }
  assert.strictEqual(errors.length, 0);
};

function printGraph(hooks) {
  const ids = {};
  const uidtoid = {};
  const activities = pruneTickObjects(hooks.activities);
  const graph = [];
  activities.forEach(procesNode);

  function procesNode(x) {
    const key = x.type.replace(/WRAP/, '').toLowerCase();
    if (!ids[key]) ids[key] = 1;
    const id = `${key}:${ids[key]++}`;
    uidtoid[x.uid] = id;
    const triggerAsyncId = uidtoid[x.triggerAsyncId] || null;
    graph.push({ type: x.type, id, triggerAsyncId });
  }
  inspect(graph);
};

module.exports = {
  checkInvocations,
  initHooks,
  printGraph,
  tick,
  verifyGraph
};
