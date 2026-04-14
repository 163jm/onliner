'use strict';
'require view';
'require rpc';
'require poll';
'require ui';

const callGetDevices = rpc.declare({
    object: 'luci.onliner',
    method: 'get_devices',
    expect: { '': {} }
});

const callSetCustomName = rpc.declare({
    object: 'luci.onliner',
    method: 'set_custom_name',
    params: ['mac', 'name'],
    expect: { '': {} }
});

function formatTime(ts) {
    if (!ts || ts === 0) return '-';
    const d = new Date(ts * 1000);
    return d.toLocaleString();
}

function formatUptime(ts) {
    if (!ts || ts === 0) return '-';
    const secs = Math.floor(Date.now() / 1000) - ts;
    if (secs < 0) return '-';
    const d = Math.floor(secs / 86400);
    const h = Math.floor((secs % 86400) / 3600);
    const m = Math.floor((secs % 3600) / 60);
    if (d > 0) return d + '天 ' + h + '小时';
    if (h > 0) return h + '小时 ' + m + '分';
    return m + '分钟';
}

function getDisplayName(device) {
    return device.custom_name || device.name || '?';
}

return view.extend({
    render() {
        const container = E('div', { 'class': 'cbi-map' });

        const header = E('div', { 'class': 'cbi-section' }, [
            E('div', { 'style': 'display:flex; align-items:center; justify-content:space-between; margin-bottom:12px;' }, [
                E('h3', { 'style': 'margin:0;' }, '在线用户'),
            ]),
            E('div', { 'id': 'onliner-summary', 'style': 'color:#666; margin-bottom:8px;' }, '加载中...')
        ]);

        const tableWrap = E('div', { 'class': 'cbi-section' }, [
            E('div', { 'class': 'table-responsive' }, [
                E('table', {
                    'id': 'onliner-table',
                    'class': 'table cbi-section-table',
                    'style': 'width:100%;'
                }, [
                    E('thead', {}, [
                        E('tr', { 'class': 'cbi-section-table-titles' }, [
                            E('th', { 'class': 'cbi-section-table-cell' }, '状态'),
                            E('th', { 'class': 'cbi-section-table-cell' }, '主机名'),
                            E('th', { 'class': 'cbi-section-table-cell' }, 'IP 地址'),
                            E('th', { 'class': 'cbi-section-table-cell' }, 'MAC 地址'),
                            E('th', { 'class': 'cbi-section-table-cell' }, '接口'),
                            E('th', { 'class': 'cbi-section-table-cell' }, '在线时长'),
                            E('th', { 'class': 'cbi-section-table-cell' }, '上线时间'),
                            E('th', { 'class': 'cbi-section-table-cell' }, '下线时间'),
                        ])
                    ]),
                    E('tbody', { 'id': 'onliner-tbody' }, [
                        E('tr', {}, [
                            E('td', { 'colspan': '8', 'style': 'text-align:center; padding:20px;' }, '加载中...')
                        ])
                    ])
                ])
            ])
        ]);

        container.appendChild(header);
        container.appendChild(tableWrap);

        // 渲染函数
        function renderDevices(data) {
            const devices = (data && data.devices) ? data.devices : [];

            // 排序：在线优先，然后按上线时间倒序
            devices.sort((a, b) => {
                if (a.status === 'online' && b.status !== 'online') return -1;
                if (a.status !== 'online' && b.status === 'online') return 1;
                return (b.last_online || 0) - (a.last_online || 0);
            });

            const onlineCount = devices.filter(d => d.status === 'online').length;
            const summary = document.getElementById('onliner-summary');
            if (summary) {
                summary.textContent = '共 ' + devices.length + ' 台设备，当前在线 ' + onlineCount + ' 台';
            }

            const tbody = document.getElementById('onliner-tbody');
            if (!tbody) return;
            tbody.innerHTML = '';

            if (devices.length === 0) {
                tbody.appendChild(E('tr', {}, [
                    E('td', { 'colspan': '8', 'style': 'text-align:center; padding:20px;' }, '暂无设备记录')
                ]));
                return;
            }

            devices.forEach((device, idx) => {
                const isOnline = device.status === 'online';
                const displayName = getDisplayName(device);

                const statusCell = E('td', {}, [
                    E('span', {
                        'style': 'display:inline-block; width:10px; height:10px; border-radius:50%; background:' +
                            (isOnline ? '#2ecc71' : '#e74c3c') + '; margin-right:6px;'
                    }),
                    isOnline ? '在线' : '离线'
                ]);

                // 主机名可点击修改
                const nameCell = E('td', {}, [
                    E('span', {
                        'style': 'cursor:pointer; border-bottom:1px dashed #999;',
                        'title': '点击修改名称',
                        'click': function(ev) {
                            const span = ev.target;
                            poll.stop();
                            const input = E('input', {
                                'type': 'text',
                                'value': displayName,
                                'style': 'width:120px; padding:2px 4px;',
                                'keydown': function(e) {
                                    if (e.key === 'Enter') saveBtn.click();
                                    if (e.key === 'Escape') {
                                        span.style.display = '';
                                        input.remove();
                                        saveBtn.remove();
                                        cancelBtn.remove();
                                        poll.start();
                                    }
                                }
                            });
                            const saveBtn = E('button', {
                                'class': 'btn cbi-button cbi-button-apply',
                                'style': 'padding:2px 6px; margin-left:4px; font-size:12px;',
                                'click': function() {
                                    const newName = input.value.trim();
                                    callSetCustomName(device.mac, newName).then(() => {
                                        device.custom_name = newName;
                                        span.textContent = newName || device.name || '?';
                                        span.style.display = '';
                                        input.remove();
                                        saveBtn.remove();
                                        cancelBtn.remove();
                                        poll.start();
                                    });
                                }
                            }, '✓');
                            const cancelBtn = E('button', {
                                'class': 'btn cbi-button',
                                'style': 'padding:2px 6px; margin-left:2px; font-size:12px;',
                                'click': function() {
                                    span.style.display = '';
                                    input.remove();
                                    saveBtn.remove();
                                    cancelBtn.remove();
                                    poll.start();
                                }
                            }, '✗');
                            span.style.display = 'none';
                            span.parentNode.appendChild(input);
                            span.parentNode.appendChild(saveBtn);
                            span.parentNode.appendChild(cancelBtn);
                            input.focus();
                            input.select();
                        }
                    }, displayName)
                ]);

                const row = E('tr', {
                    'class': 'cbi-section-table-row cbi-rowstyle-' + ((idx % 2) + 1),
                    'style': isOnline ? '' : 'opacity:0.6;'
                }, [
                    statusCell,
                    nameCell,
                    E('td', {}, device.ip || '-'),
                    E('td', { 'style': 'font-family:monospace; font-size:13px;' }, device.mac || '-'),
                    E('td', {}, device.interface || '-'),
                    E('td', {}, isOnline ? formatUptime(device.uptime) : '-'),
                    E('td', {}, device.last_online ? formatTime(device.last_online) : '-'),
                    E('td', {}, isOnline ? '-' : (device.last_offline ? formatTime(device.last_offline) : '-'))
                ]);

                tbody.appendChild(row);
            });
        }

        // 首次加载
        callGetDevices().then(renderDevices);

        // 定时刷新 5 秒
        poll.add(() => callGetDevices().then(renderDevices), 5);

        return container;
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
