#!/usr/bin/env node
// Раздаёт один файл по локальной сети по короткой ссылке.
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { randomInt } from 'node:crypto';
import { createServer } from 'node:http';
import { networkInterfaces } from 'node:os';
import { basename, resolve } from 'node:path';
import { pipeline } from 'node:stream';
import { parseArgs } from 'node:util';

const DEFAULT_PORT = 8080;
const PORT_ATTEMPTS = 20;
// Ссылку набирают руками, поэтому без похожих символов (0/o, 1/l/i).
const TOKEN_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';
const TOKEN_LENGTH = 6;
const VPN_ADAPTER = /vpn|amnezia|wireguard|\bwg\d*|tailscale|zerotier|\btun\d*|\btap\d*|utun/i;
const VIRTUAL_ADAPTER = /virtual|vmware|vbox|hyper-v|vethernet|wsl|docker|veth|br-/i;

const USAGE = `Использование: node share.js <файл> [--port 8080] [--ip 192.168.1.5]

  --port  порт сервера (по умолчанию ${DEFAULT_PORT}, если занят — берётся следующий свободный)
  --ip    адрес для ссылки, если автоматически выбран не тот`;

function createToken() {
  let token = '';
  for (let i = 0; i < TOKEN_LENGTH; i++) token += TOKEN_ALPHABET[randomInt(TOKEN_ALPHABET.length)];
  return token;
}

function addressRank({ name, address }) {
  let rank = 0;
  if (address.startsWith('192.168.')) rank = 3;
  else if (/^172\.(1[6-9]|2\d|3[01])\./.test(address)) rank = 2;
  else if (address.startsWith('10.')) rank = 1;
  // VPN и виртуальные адаптеры тоже имеют частные адреса, но второе устройство через них не достучится.
  return VPN_ADAPTER.test(name) || VIRTUAL_ADAPTER.test(name) ? rank - 10 : rank;
}

// Адреса этого компьютера: первым идёт самый похожий на домашнюю сеть.
function findLanAddresses() {
  return Object.entries(networkInterfaces())
    .flatMap(([name, entries]) => entries.map((entry) => ({ ...entry, name })))
    .filter((entry) => entry.family === 'IPv4' && !entry.internal && !entry.address.startsWith('169.254.'))
    .sort((a, b) => addressRank(b) - addressRank(a));
}

function contentDisposition(fileName) {
  const ascii = fileName.replace(/[^\x20-\x7e]|["\\]/g, '_');
  const encoded = encodeURIComponent(fileName).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encoded}`;
}

// null — заголовка нет или он нам непонятен (отдаём файл целиком), 'unsatisfiable' — диапазон вне файла.
function parseRange(header, size) {
  const match = /^bytes=(\d*)-(\d*)$/.exec(header?.trim() ?? '');
  if (!match || (!match[1] && !match[2])) return null;

  const [, from, to] = match;
  const start = from ? Number(from) : Math.max(size - Number(to), 0);
  const end = from && to ? Math.min(Number(to), size - 1) : size - 1;
  if (start >= size || start > end || (!from && Number(to) === 0)) return 'unsatisfiable';
  return { start, end };
}

function formatSize(bytes) {
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  const power = bytes > 0 ? Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1) : 0;
  return `${(bytes / 1024 ** power).toFixed(power ? 1 : 0)} ${units[power]}`;
}

function sendText(res, status, text, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', ...headers });
  res.end(text);
}

function log(message) {
  console.log(`[${new Date().toLocaleTimeString()}] ${message}`);
}

async function handleRequest(req, res, filePath, token) {
  const requested = req.url.split('?')[0].replace(/^\/+|\/+$/g, '').toLowerCase();
  if (requested !== token) return sendText(res, 404, 'Неверная ссылка');
  if (req.method !== 'GET' && req.method !== 'HEAD') return sendText(res, 405, 'Метод не поддерживается', { Allow: 'GET, HEAD' });

  let info;
  try {
    info = await stat(filePath);
  } catch {
    return sendText(res, 410, 'Файл больше недоступен');
  }

  const etag = `"${info.size.toString(16)}-${Math.floor(info.mtimeMs).toString(16)}"`;
  const lastModified = info.mtime.toUTCString();
  const ifRange = req.headers['if-range'];
  // Докачка возможна, только если файл не менялся с начала скачивания.
  const range = !ifRange || ifRange === etag || ifRange === lastModified ? parseRange(req.headers.range, info.size) : null;

  if (range === 'unsatisfiable') return sendText(res, 416, 'Неверный диапазон', { 'Content-Range': `bytes */${info.size}` });

  const start = range?.start ?? 0;
  const end = range?.end ?? info.size - 1;
  const length = end - start + 1;

  res.writeHead(range ? 206 : 200, {
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': contentDisposition(basename(filePath)),
    'Content-Length': length,
    'Accept-Ranges': 'bytes',
    ETag: etag,
    'Last-Modified': lastModified,
    ...(range && { 'Content-Range': `bytes ${start}-${end}/${info.size}` }),
  });

  if (req.method === 'HEAD' || length === 0) return res.end();

  const client = req.socket.remoteAddress?.replace(/^::ffff:/, '');
  log(`${client}: скачивание начато (${formatSize(length)})`);
  pipeline(createReadStream(filePath, { start, end }), res, (error) => {
    log(`${client}: ${error ? 'скачивание прервано' : 'скачивание завершено'}`);
  });
}

async function main() {
  let args;
  try {
    args = parseArgs({ allowPositionals: true, options: { port: { type: 'string' }, ip: { type: 'string' } } });
  } catch (error) {
    console.error(`${error.message}\n\n${USAGE}`);
    process.exit(1);
  }

  const [file] = args.positionals;
  if (!file) {
    console.error(USAGE);
    process.exit(1);
  }

  const filePath = resolve(file);
  const info = await stat(filePath).catch(() => null);
  if (!info?.isFile()) {
    console.error(`Файл не найден: ${filePath}`);
    process.exit(1);
  }

  const explicitPort = args.values.port !== undefined;
  let port = explicitPort ? Number(args.values.port) : DEFAULT_PORT;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error(`Неверный порт: ${args.values.port}`);
    process.exit(1);
  }

  const adapters = findLanAddresses();
  const ip = args.values.ip ?? adapters[0]?.address;
  if (!ip) {
    console.error('Не найден адрес в локальной сети. Проверьте подключение к Wi-Fi или укажите --ip.');
    process.exit(1);
  }

  const token = createToken();
  const server = createServer((req, res) => {
    handleRequest(req, res, filePath, token).catch((error) => {
      console.error(error);
      res.destroy();
    });
  });

  let attempts = 1;
  server.on('error', (error) => {
    if (error.code === 'EADDRINUSE' && !explicitPort && attempts < PORT_ATTEMPTS) {
      attempts++;
      server.listen(++port, '0.0.0.0');
      return;
    }
    console.error(error.code === 'EADDRINUSE' ? `Порт ${port} занят.` : error.message);
    process.exit(1);
  });

  server.on('listening', () => {
    const link = (host) => `http://${host}:${port}/${token}`;
    console.log(`\nФайл:   ${basename(filePath)} (${formatSize(info.size)})`);
    console.log(`Ссылка: ${link(ip)}\n`);

    const others = adapters.filter((entry) => entry.address !== ip && addressRank(entry) >= 0);
    if (others.length) {
      console.log('Если ссылка не открывается, попробуйте другие адреса этого компьютера:');
      for (const { address } of others) console.log(`  ${link(address)}`);
      console.log();
    }

    const vpns = adapters.filter((entry) => VPN_ADAPTER.test(entry.name));
    if (vpns.length) {
      const names = vpns.map((entry) => entry.name).join(', ');
      console.log(`Внимание: включён VPN (${names}). Он может перехватывать трафик локальной сети, и тогда второе устройство не подключится. В этом случае отключите VPN или исключите из него локальную сеть.
`);
    }
    console.log('Оба устройства должны быть в одной сети Wi-Fi. Остановить раздачу: Ctrl+C\n');
  });

  server.listen(port, '0.0.0.0');
}

main();
