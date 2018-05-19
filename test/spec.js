/* eslint-disable no-console */
/* eslint-disable no-undef */
/* eslint-disable no-unused-vars */

const should = require('should')
const { request } = require('http')
const { parse } = require('url')
const { createSocket } = require('../')

function get({ url, headers }) {
	const options = parse(url)
	options.headers = headers
	return new Promise((ok, fail) => {
		request(options, res => {
			const body = []
			res.on('data', chunk => body.push(chunk.toString()))
			res.on('end', () => {
				res.text = body.join('')
				ok(res)
			})
		}).on('error', fail).end()
	})
}

describe('http tests', () => {

	let server

	before(done => {
		done()
	})

	after(done => {
		done()
	})

	it('should start a server', async () => {
		const r200 = 'HTTP/1.1 200 OK\r\nServer: http-server\r\nContent-Type: application/json; charset=utf-8\r\nConnection: keep-alive\r\nContent-Length: 21\r\n\r\n{"message":"Testing"}'
		const sock = createSocket(1, 0)
		sock.onConnect(fd => sock.setup(fd, new Buffer(4096), new Buffer(4096)))
		sock.onRequest(fd => sock.writeText(fd, 0, r200))
		const r = sock.listen('127.0.0.1', 3000)
		r.should.equal(0)
		server = sock
	});

	it('should get a 200 OK with expected body', async () => {
		const url = 'http://127.0.0.1:3000/'
		const headers = {}
		const res = await get({ url, headers })
		res.should.have.properties(['httpVersionMajor', 'httpVersionMinor', 'statusCode', 'statusMessage', 'headers'])
		res.httpVersionMajor.should.equal(1)
		res.httpVersionMinor.should.equal(1)
		res.statusCode.should.equal(200)
		res.statusMessage.should.equal('OK')
		res.headers.should.have.properties(['server', 'connection', 'content-length', 'content-type'])
		res.headers.connection.should.equal('keep-alive')
		res.headers.server.should.equal('http-server')
		res.headers['content-length'].should.equal('21')
		res.headers['content-type'].should.equal('application/json; charset=utf-8')
		const body = JSON.parse(res.text)
		body.should.have.properties(['message'])
		body.message.should.equal('Testing')
		server.close()
	})

})
