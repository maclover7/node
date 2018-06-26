'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');
const assert = require('assert');
const h2 = require('http2');

const server = h2.createServer();

server.on(
  'stream',
  common.mustCall((stream) => {
    stream.on('finish', () => {
      console.log('finished');
    });

    stream.respond({
      'content-type': 'text/html',
      ':status': 200
    });
    stream.end('hello world');
  })
);

server.listen(
  0,
  common.mustCall(() => {
    const client = h2.connect(`http://localhost:${server.address().port}`, {
      settings: {
        enablePush: false,
        initialWindowSize: 123456
      }
    });

    const req = client.request({ ':path': '/' });
    req.on('response', common.mustCall());
    req.resume();
    req.on('end', common.mustCall(() => {
      server.close();
      client.close();
    }));
    req.end();
  })
);
