const RUNTIME = (typeof window !== 'undefined') ? 'browser' : ((typeof process !== 'undefined') ? ((typeof Bun !== 'undefined') ? 'bun' : 'node') : 'unknown');

if (RUNTIME === 'unknown') {
    throw new Error('Unsupported JavaScript runtime');
}

let exports = {};

const DEFAULT_PART_SIZE = 25 * 1024 * 1024; // 25 MB
exports.DEFAULT_PART_SIZE = DEFAULT_PART_SIZE;

// base16 (hex) encode, decode
function b16e(buffer) {
    const bytes = new Uint8Array(buffer);
    const hex = new Array(bytes.length * 2);
    for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i];
        hex[i * 2] = byte.toString(16).padStart(2, '0')[0];
        hex[i * 2 + 1] = byte.toString(16).padStart(2, '0')[1];
    }
    return hex.join('');
}
function b16d(hex) {
    if (hex.length % 2 !== 0) {
        throw new Error('Hex strings must have an even number of characters.');
    }

    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}
function encodeNumber(n) {
    const view = new DataView(new ArrayBuffer(4));
    view.setUint32(0, n, true);
    return new Uint8Array(view.buffer);
}
function decodeNumber(buffer, offset = 0) {
    const view = new DataView(buffer.buffer);
    return Number(view.getUint32(offset, true));
}
function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}
exports.functions = { b16e, b16d, encodeNumber, decodeNumber, formatBytes };

class Logger {
    constructor(level = 4) {
        this.level = level;
    }
    error(name, ...args) {
        if (this.level > 0) console.error(`[${name}][ERROR]:`, ...args);
    }
    warn(name, ...args) {
        if (this.level > 1) console.warn(`[${name}][WARN]:`, ...args);
    }
    log(name, ...args) {
        if (this.level > 2) console.log(`[${name}][LOG]:`, ...args);
    }
    info(name, ...args) {
        if (this.level > 3) console.info(`[${name}][INFO]:`, ...args);
    }
}
const logger = new Logger(3);
exports.logger = logger;

class Encrypction {
    makeKey() {
        return b16e(crypto.getRandomValues(new Uint8Array(32)));
    }
    async _importKey(key) {
        if (typeof key === 'string') key = b16d(key);
        return await crypto.subtle.importKey(
            'raw',
            key,
            {
                name: 'AES-GCM',
                length: key.byteLength * 8
            },
            true,
            ['encrypt', 'decrypt']
        );
    }
    async encrypt(key, buffer) {
        if (!(key instanceof CryptoKey)) key = await this._importKey(key);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv
            },
            key,
            buffer
        );
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), iv.length);
        return combined;
    }
    async decrypt(key, buffer) {
        if (!(key instanceof CryptoKey)) key = await this._importKey(key);
        if (!(buffer instanceof Uint8Array)) buffer = new Uint8Array(buffer);
        const iv = buffer.subarray(0, 12);
        const encrypted = buffer.subarray(12);
        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv
            },
            key,
            encrypted
        );
        return new Uint8Array(decrypted);
    }
}
const encryption = new Encrypction();
exports.encryption = encryption;

class Client {
    constructor(url, key) {
        this.url = url;
        this.key = key;
    }
    async _query(header = {}, data = new Uint8Array(0), tries = 5) {
        header = (new TextEncoder()).encode(JSON.stringify(header));
        let payload = new Uint8Array(4 + header.byteLength + data.byteLength);
        payload.set(encodeNumber(header.byteLength), 0);
        payload.set(header, 4);
        payload.set(data, 4 + header.byteLength);
        payload = await encryption.encrypt(this.key, payload);
        let response;
        let t = 0;
        while (true) {
            t += 1;
            try {
                response = await fetch(this.url, { method: 'POST', body: payload });
            } catch (e) {
                logger.warn('CLIENT', 'Failed to query server: ' + e.message);
            }
            if (response && response.status === 200) break;
            if (t >= tries) throw new Error('Failed to query server after ' + tries + ' tries.');
            await new Promise(r => setTimeout(r, 1000));
        }
        const responsePayload = await encryption.decrypt(this.key, await response.arrayBuffer());
        const responseHeaderLength = decodeNumber(responsePayload, 0);
        const responseHeader = new TextDecoder().decode(responsePayload.subarray(4, 4 + responseHeaderLength));
        const responseData = responsePayload.subarray(4 + responseHeaderLength);
        return { header: JSON.parse(responseHeader), data: responseData };
    }
    async ping() {
        const r = await this._query({ command: 'ping' });
        if (r.header.ok) return true;
        throw new Error('Failed to ping server: ' + r.header.error);
    }
    async getInfo() {
        const r = await this._query({ command: 'info' });
        if (r.header.ok) return { mode: r.header.mode, files: r.header.files };
        throw new Error('Failed to get info: ' + r.header.error);
    }
    async getPart(file, part) {
        const r = await this._query({ command: 'get-part', file, part });
        if (r.header.ok) return r.data;
        throw new Error('Failed to get part: ' + r.header.error);
    }
}
exports.Client = Client;

if (RUNTIME !== 'browser') {
    const http = await import('http');
    const os = await import('os');
    const pathlib = await import('path');
    const fs = await import('fs');
    const CP = await import('child_process');
    const urllib = await import('url');
    //const { v4: uuid } = await import('uuid');

    async function generateFilesInfo(path, root = '') {
        let files = [];
        const stat = await fs.promises.stat(path);
        if (stat.isFile()) {
            let p = (root ? root + '/' : '') + pathlib.basename(path);
            if (p.startsWith('./')) p = p.slice(2);
            files.push({ path: p, name: pathlib.basename(path), size: stat.size, parts: Math.ceil(stat.size / DEFAULT_PART_SIZE) });
        } else if (stat.isDirectory()) {
            for (const f of await fs.promises.readdir(path)) {
                files = files.concat(await generateFilesInfo(pathlib.join(path, f), (root ? root + '/' : '') + pathlib.basename(path)));
            }
        }
        return files;
    }
    exports.functions.generateFilesInfo = generateFilesInfo;

    class Arguments {
        constructor(argv) {
            this.argv = argv;
        }
        _parseValue(arg) {
            if (arg.toLowerCase() === 'true') return true;
            if (arg.toLowerCase() === 'false') return false;
            if (!isNaN(arg)) return Number(arg);
            return arg;
        }
        parse() {
            const argv = this.argv.map(a => a); // clone
            const args = { _: [] };
            args.binary = argv.shift();
            args.script = argv.shift();
            let lastArg = null;
            while (argv.length > 0) {
                const arg = argv.shift();
                if (arg.startsWith('--')) {
                    if (lastArg !== null) {
                        const aname = lastArg.substr(2);
                        args[aname] = true;
                    }
                    lastArg = arg;
                } else if (lastArg !== null) {
                    const aname = lastArg.substr(2);
                    if (typeof args[aname] !== 'undefined') {
                        if (Array.isArray(args[aname])) {
                            args[aname].push(this._parseValue(arg));
                        } else {
                            args[aname] = [args[aname], this._parseValue(arg)];
                        }
                    } else {
                        args[aname] = this._parseValue(arg);
                    }
                    lastArg = null;
                } else {
                    args._.push(this._parseValue(arg));
                }
            }
            if (lastArg !== null) {
                const aname = lastArg.substr(2);
                args[aname] = true;
            }
            return args;
        }
    }
    const args = (new Arguments(process.argv)).parse();
    exports.args = args;
    logger.level = !isNaN(args['log-level']) ? args['log-level'] : 3;

    if (args.help || (args._.length > 0 && (args._[0].toLowerCase() === 'help' || args._[0].toLowerCase() === '-h'))) {
        console.log('FastTransfer CLI Usage:');
        console.log(`  ${args.binary} ${args.script} [command] [options]`);
        console.log(`  ${args.binary} ${args.script} transfer-code [options]`);
        console.log(`  ${args.binary} ${args.script} share local-files-to-share [options]`);
        console.log('Commands:');
        console.log('  help                             Show this help message.');
        console.log('    --help, -h');
        //console.log('  serve                            Start a server waiting to receive files. (default)');
        console.log('  share [files]                    Start a server sharing files.');
        //console.log('  send [transfer-code] [files]     Send files to a server.');
        console.log('  download [transfer-code]         Download files from a server.');
        console.log('Options:');
        console.log('  --log-level                      Set the logging level (0-4). (default: 3)');
        console.log('  --local                          Do not use cloudflared to expose the server to the internet. (default: false)');
        //console.log('  --no-prompt                      Do not ask for confirmation before accepting incoming files in serve mode.');
        console.log('  --threads                        Number of threads (concurrent connections) to use when downloading files. (default: 4)');
        process.exit(0);
    }

    logger.info('MAIN', 'Initializing...');
    logger.info('MAIN', `JavaScript runtime: ${RUNTIME}`);

    class FDBalancer {
        constructor(maxFDs = 1024) {
            this.fds = {};
            this.maxFDs = maxFDs;
            this.locks = {};
        }
        async _removeOldest() {
            let oldest = null;
            for (const path in this.fds) {
                if (!oldest || this.fds[path].lastAccess < this.fds[oldest].lastAccess) oldest = path;
            }
            logger.info('FDBalancer', `Closing file descriptor for "${oldest}"`);
            await this.fds[oldest].fd.close();
            delete this.fds[oldest];
        }
        async _access(path) {
            while (!this.fds[path] && this.locks[path]) await new Promise(resolve => setTimeout(resolve, 10));
            if (!this.fds[path]) {
                this.locks[path] = true;
                if (Object.keys(this.fds).length >= this.maxFDs) await this._removeOldest();
                logger.info('FDBalancer', `Opening file descriptor for "${path}"`);
                this.fds[path] = { fd: await fs.promises.open(path, 'r'), lastAccess: Date.now() };
                delete this.locks[path];
            }
            this.fds[path].lastAccess = Date.now();
        }
        async read(path, buffer, offset, length, position) {
            await this._access(path);
            return await this.fds[path].fd.read(buffer, offset, length, position);
        }
    }

    class BaseServer {
        constructor() {
            this.server = null;
            this.address = null;
            this.onInfo = this.notImplemented;
            this.onGetPart = this.notImplemented;
            this.key = encryption.makeKey();
        }
        async _reply(res, header = {}, data = Buffer.alloc(0)) {
            header = Buffer.from(JSON.stringify(header));
            res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
            res.end(await encryption.encrypt(this.key, Buffer.concat([encodeNumber(header.length), header, data])));
            await new Promise((r) => res.once('close', r));
        }
        async notImplemented(header, data, response) {
            await response({ ok: false, error: 'Not implemented.' }, Buffer.alloc(0));
        }
        start(host = '0.0.0.0', port = 0) {
            return new Promise((resolve) => {
                this.server = new http.Server((req, res) => {
                    let body = [];
                    req.on('data', chunk => {
                        body.push(chunk);
                    }).on('end', async () => {
                        try {
                            body = Buffer.concat(body);
                            body = Buffer.from(await encryption.decrypt(this.key, body));
                            const headlength = Number(body.readUInt32LE(0));
                            const header = JSON.parse(body.subarray(4, 4 + headlength).toString('utf8'));
                            const data = body.subarray(4 + headlength);
                            if (header.command === 'ping') {
                                await this._reply(res, { ok: true }, Buffer.alloc(0));
                            } else if (header.command === 'info') {
                                await this.onInfo(header, data, async (header, data) => await this._reply(res, header, data));
                            } else if (header.command === 'get-part') {
                                await this.onGetPart(header, data, async (header, data) => await this._reply(res, header, data));
                            } else {
                                await this._reply(res, { ok: false, error: 'Unknown command: ' + header.command }, data);
                            }
                        } catch (e) {
                            logger.error('SERVER', 'Failed to process request: ' + e.message);
                            try {
                                await this._reply(res, { ok: false, error: 'Failed to process request.' }, Buffer.alloc(0));
                            } catch (e) { }
                            throw e;
                        }
                    });
                });
                this.server.listen(port, host, () => {
                    this.address = this.server.address();
                    resolve(this.address);
                });
            });
        }
    }
    exports.BaseServer = BaseServer;

    class LineWriter {
        constructor() {
            this.lastLength = 0;
            this.lastLine = '';
        }
        rewrite(line) {
            if (line == this.lastLine) return;
            this.lastLine = line;
            process.stdout.write('\r' + line);
            if (line.length < this.lastLength) {
                process.stdout.write(' '.repeat(this.lastLength - line.length));
            }
            this.lastLength = line.length;
        }
        clear() {
            this.rewrite('');
            process.stdout.write('\r');
        }
    }
    const lineWriter = new LineWriter();
    exports.lineWriter = lineWriter;

    class Cloudflared {
        constructor() {
            this.process = null;
            this.hostname = null;
            this.running = false;
            this.exited = false;
            this.killed = false;
        }
        _cloudflaredExeName() {
            const dir = pathlib.join(os.tmpdir(), 'fasttransfer');
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            if (process.platform == 'win32') {
                return dir + '\\cloudflared.exe';
            } else {
                return dir + '/cloudflared';
            }
        }
        _archMap(a) {
            switch (a) {
                case 'ia32':
                    return '386';
                case 'x64':
                    return 'amd64';
                default:
                    return a;
            }
        }
        async download() {
            if (process.platform == 'win32') {
                const url = `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-${this._archMap(process.arch)}.exe`;
                const request = await fetch(url, { redirect: 'follow' });
                if (request.status != 200) throw new Error('Failed to download cloudflared.');
                const data = await request.arrayBuffer();
                await fs.promises.writeFile(this._cloudflaredExeName(), Buffer.from(data));
            } else if (process.platform == 'linux') {
                const url = `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${this._archMap(process.arch)}`;
                const request = await fetch(url, { redirect: 'follow' });
                if (request.status != 200) throw new Error('Failed to download cloudflared.');
                const data = await request.arrayBuffer();
                await fs.promises.writeFile(this._cloudflaredExeName(), Buffer.from(data));
                await fs.promises.chmod(this._cloudflaredExeName(), 0o755); // make it executable
            } else {
                throw new Error('Platform not implemented.');
            }
        }
        async run({ url, wait, timeout, dnsDelay } = {}) {
            if (!url) throw new Error('URL is required');
            if (typeof wait !== 'boolean') wait = false;
            if (typeof timeout !== 'number') timeout = 60000;
            if (typeof dnsDelay !== 'number') dnsDelay = 20000; // a delay to wait for cloudflare to set up DNS
            if (!fs.existsSync(this._cloudflaredExeName())) {
                await this.download();
            }
            if (this.process) {
                try {
                    this.process.kill();
                } catch (e) { }
            }
            this.process = null;
            this.hostname = null;
            this.killed = false;
            this.exited = false;
            this.running = true;
            this.process = CP.spawn(this._cloudflaredExeName(), ['tunnel', '--url', url]);
            this.process.stderr.on('data', async (data) => {
                //logger.error('CLOUDFLARED', data.toString('utf-8'));
                const match = data.toString('utf-8').match(/https\:\/\/(.*)\.trycloudflare\.com/i);
                if (match) {
                    await new Promise(r => setTimeout(r, dnsDelay));
                    this.hostname = match[1] + '.trycloudflare.com';
                }
            });
            this.process.on('exit', (code, signal) => {
                this.process = null;
                this.hostname = null;
                this.exited = true;
                this.running = false;
                logger.error('CLOUDFLARED', `Cloudflared exited with code ${code} and signal ${signal}!`);
            });
            if (wait) return await this.waitForHostname(timeout);
        }
        async waitForHostname(timeout = 60000) {
            const t = setTimeout(() => {
                if (!this.hostname) {
                    this.kill();
                    throw new Error('Timed out waiting for hostname after ' + timeout + 'ms.');
                }
            }, timeout);
            while (!this.hostname) await new Promise(resolve => setTimeout(resolve, 10));
            clearTimeout(t);
            return this.hostname;
        }
        async kill() {
            if (this.process) {
                try {
                    this.process.kill();
                } catch (e) { }
                this.process = null;
                this.hostname = null;
                this.killed = true;
                this.exited = false;
                this.running = false;
            }
        }
    }
    exports.Cloudflared = Cloudflared;

    async function mainCLI() {
        if (args._[0] == 'share') {
            logger.log('MAIN', 'Starting server to share files...');
            let files = args._.slice(1);
            if (!files.length) files = ['.'];
            let finfo = [];
            for (const f of files) {
                finfo = finfo.concat(await generateFilesInfo(f));
            }
            let bytesSent = 0;
            let lastBytesSent = 0;
            const server = new BaseServer();
            server.onInfo = async (header, data, response) => {
                await response({
                    ok: true,
                    mode: 'share',
                    files: finfo
                }, Buffer.alloc(0));
            }
            const fds = new FDBalancer();
            server.onGetPart = async (header, data, response) => {
                const path = pathlib.normalize(header.file).replace(/\\/g, '/');
                let i = null;
                for (const f of finfo) {
                    if (f.path == path) {
                        i = f;
                        break;
                    }
                }
                if (!i) {
                    await response({ ok: false, error: 'File not found.' }, Buffer.alloc(0));
                    return;
                }
                const part = header.part;
                const offset = DEFAULT_PART_SIZE * (part - 1);
                const size = (offset + DEFAULT_PART_SIZE) > i.size ? i.size - offset : DEFAULT_PART_SIZE;
                const buffer = Buffer.alloc(size);
                await fds.read(path, buffer, 0, size, offset);
                await response({ ok: true }, buffer);
                bytesSent += size;
            }
            const address = await server.start();
            logger.log('MAIN', `Sharing ${finfo.length} files (${formatBytes(finfo.reduce((a, b) => a + b.size, 0))}).`);
            let code;
            if (!args.local) {
                logger.log('MAIN', 'Starting cloudflared, please wait...');
                const CF = new Cloudflared();
                try {
                    await CF.run({ url: `http://127.0.0.1:${address.port}`, wait: true });
                } catch (e) {
                    logger.error('MAIN', 'Failed to start cloudflared:', e);
                    process.exit(1);
                }
                code = `r:${server.key}:https:${CF.hostname}`;
                logger.log('MAIN', 'Public trasfer code:', code);
            } else {
                code = `r:${server.key}:http:LOCALIP:${address.port}`;
                logger.log('MAIN', 'Local trasfer code (copy and paste your computer\'s ip address):', code);
            }
            logger.log('MAIN', 'To use:');
            logger.log('MAIN', `\t(Ba)sh/cmd: curl https://ts.westhedev.xyz | node - ${code}`);
            logger.log('MAIN', `\tPowershell: irm  https://ts.westhedev.xyz | node - ${code}`);
            const realServerStartTime = Date.now();
            let serverStartTime;
            while (true) {
                if (bytesSent == 0) {
                    serverStartTime = Date.now(); // don't start counting until we actually do something
                }
                lineWriter.rewrite(`Bytes sent: ${formatBytes(bytesSent)} (${formatBytes(bytesSent - lastBytesSent)}/s - ${formatBytes(bytesSent / ((Date.now() - serverStartTime) / 1000))}/s avg), Time serving: ${Math.round((Date.now() - realServerStartTime) / 1000)}s`);
                lastBytesSent = bytesSent;
                await new Promise(resolve => setTimeout(resolve, 500));
            }
        } else if (args._.length > 0) {
            let code;
            const codeMatch = (/(?:r|s)\:[0-9a-fA-F]{64}\:https?\:.*/gi);
            if (args._[0].match(codeMatch)) {
                code = args._[0];
            } else if (args._[0] == 'download' && args._.length > 1 && args._[1].match(codeMatch)) {
                code = args._[1];
            } else {
                logger.error('ERROR', 'No valid command or transfer code provided.');
                process.exit(1);
            }
            code = code.split(':');
            code = {
                mode: code[0],
                key: code[1],
                proto: code[2],
                host: code[3],
                port: code[4] || (code[2] == 'http' ? 80 : 443)
            };

            logger.log('MAIN', 'Attempting to connect to server...');
            let client;
            try {
                client = new Client(`${code.proto}://${code.host}:${code.port}`, code.key);
                await client.ping();
            } catch (e) {
                logger.error('MAIN', 'Failed to connect to server:', e.message);
                logger.error('MAIN', 'Make sure the transfer code is correct and the server is running.');
                process.exit(1);
            }

            const info = await client.getInfo();
            const totalSize = info.files.reduce((a, b) => a + b.size, 0);
            logger.log('MAIN', `Starting download of ${info.files.length} files (${formatBytes(totalSize)})...`);
            let filesDownloaded = 0;
            let startTime = Date.now();
            let bytesDownloaded = 0;
            let lastBytesDownloaded = 0;
            let logQueue = [];
            setImmediate(async () => {
                while (filesDownloaded < info.files.length) {
                    if (logQueue.length > 0) {
                        lineWriter.clear();
                        while (logQueue.length > 0) {
                            logger.log('MAIN', logQueue.shift());
                        }
                    }
                    lineWriter.rewrite(`Downloaded ${filesDownloaded}/${info.files.length} files - ${formatBytes(bytesDownloaded)}/${formatBytes(totalSize)} (${formatBytes(bytesDownloaded - lastBytesDownloaded)}/s - ${formatBytes(bytesDownloaded / ((Date.now() - startTime) / 1000))}/s avg)`);
                    lastBytesDownloaded = bytesDownloaded;
                    await new Promise(resolve => setTimeout(resolve, 500));
                }
                lineWriter.clear();
                logger.log('MAIN', `Download (${formatBytes(totalSize)}) complete in ${Math.round((Date.now() - startTime) / 1000)}s (${formatBytes(totalSize / ((Date.now() - startTime) / 1000))}/s)`);
                process.exit(0);
            });
            for (const file of info.files) {
                const path = pathlib.normalize(file.path).replace(/\\/g, '/');
                if (!fs.existsSync(pathlib.dirname(path))) fs.mkdirSync(pathlib.dirname(path), { recursive: true });
                const fd = await fs.promises.open(path, 'w');
                let start = Date.now();
                let running = 0;
                let writeIndex = 1;
                for (let i = 1; i <= file.parts; i++) {
                    running++;
                    const ii = parseInt(i);
                    setImmediate(async () => {
                        const data = await client.getPart(file.path, ii);
                        while (writeIndex != ii) await new Promise(resolve => setTimeout(resolve, 10));
                        await fd.write(data);
                        bytesDownloaded += data.length;
                        writeIndex++;
                        running--;
                    });
                    while (running >= (args.threads || 4)) await new Promise(resolve => setTimeout(resolve, 10));
                }
                while (running > 0) await new Promise(resolve => setTimeout(resolve, 10));
                await fd.close();
                logQueue.push(`Downloaded "${path}" (${formatBytes(file.size)}) in ${Math.round((Date.now() - start) / 1000)}s (${formatBytes(file.size / ((Date.now() - start) / 1000))}/s)`);
                filesDownloaded++;
            }
        } else {
            logger.error('ERROR', 'No valid command or transfer code provided.');
            process.exit(1);
        }
    }

    const currentFile = urllib.fileURLToPath(import.meta.url);
    const cliPaths = [currentFile, pathlib.basename(currentFile), '-', undefined];
    if (cliPaths.includes(process.argv[1])) {
        await mainCLI();
    }
}

export default exports;