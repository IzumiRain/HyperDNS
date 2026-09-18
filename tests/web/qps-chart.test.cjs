const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

const source = readFileSync(resolve(__dirname, '../../web/js/app.js'), 'utf8');
const chartCode = source.slice(source.indexOf('function pushChartData('), source.indexOf('// EVENT LISTENERS & SPA ROUTING'));
const routingCode = source.slice(source.indexOf('const tabRoutes ='), source.indexOf("window.addEventListener('popstate'"));

function fixture() {
  const chart = { data: { datasets: [{ data: Array(60).fill(0) }] }, updates: 0,
    update(mode) { assert.equal(mode, 'none'); this.updates++; } };
  const context = vm.createContext({
    qpsChart: chart, activeDashTab: '', ADMIN_BASE: '/test', DASH_BASE: '/test/dash',
    window: { location: { pathname: '/test/dash/home' } },
    document: { querySelectorAll: () => [], getElementById: () => null },
    safeFeatherReplace() {}, initChart() { throw new Error('Unexpected initialization'); },
  });
  vm.runInContext(chartCode + '\n' + routingCode, context);
  return { chart, run: code => vm.runInContext(code, context) };
}

test('/home delivers QPS samples to the rolling chart', () => {
  const { chart, run } = fixture();
  run('handleRouteFromURL(); pushChartData(12.5)');
  assert.equal(chart.data.datasets[0].data.length, 60);
  assert.equal(chart.data.datasets[0].data.at(-1), 12.5);
  assert.equal(chart.updates, 1);
});

test('other tabs skip painting and the dashboard resumes on return', () => {
  const { chart, run } = fixture();
  run("switchTab('clients', false); pushChartData(99)");
  assert.equal(chart.updates, 0);
  run("switchTab('dashboard', false); pushChartData(7)");
  assert.equal(chart.data.datasets[0].data.at(-1), 7);
  assert.equal(chart.updates, 1);
});

test('invalid samples leave gaps; zero is a valid sample', () => {
  const { chart, run } = fixture();
  run('handleRouteFromURL(); [undefined, NaN, Infinity, -1, "4", 0].forEach(pushChartData)');
  assert.deepEqual(chart.data.datasets[0].data.slice(-6), [null, null, null, null, null, 0]);
  assert.equal(chart.updates, 6);
});
