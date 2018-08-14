<script type="text/javascript"  charset="utf-8">
    
    socket.on('connect', function() {
        console.log('connected (bod)');
        socket.emit('join', {'room':'bod'});
        socket.emit('bod_latest');
    });

    socket.on('bod_data_push', function(msg) {
        console.log('recieved new bod data');
        bod_chart1.load({json:JSON.parse(msg.bod_chart1)});
        bod_chart2.load({json:JSON.parse(msg.bod_chart2)});
    })
    
    if (typeof is_printable_chart === 'undefined') {
        var is_printable_chart = false;
    }
    
    var bod_chart1 = c3.generate({
        bindto: '#bod_chart1',
        data: {
            columns: [],
            mimeType: 'json',
            x: 'x',
            types: {
                young: 'area',
                mid: 'area',
                old: 'area',
                backlog: 'line',
                total: 'line'
            },
            groups: [['young','mid','old']],
            order: null,
            colors: {
                young: '#0099cc',
                mid: '#cc7a00',
                old: '#cc0000',
                backlog: '#00aa00',
                total: '#777777'
            },
            names: {
                young: '< 30 days',
                mid: '30 - 60 days',
                old: '> 60 days',
                backlog: 'Backlog',
                total: 'Total'
            }
        },
        axis: {
            x: {
                type: 'timeseries',
                tick: {
                    format: '%Y-%m-%d',
                    count: 8
                },
                // label: {
                //     text: 'Date',
                //     position: 'outer-center'
                // }
            },
            y: {
                label: {
                    text: 'Vulnerability Count',
                    position: 'outer-middle'
                },
                min: 0,
                padding: {
                    bottom: 0
                }
            }
        },
        padding: {
            right: 20
        },
        regions: [
            // {start: '2015-04-17', end: '2015-4-24', class:'yellow'},
            // {start: '2015-04-24', class:'red'}
        ],
        point: {
          show: false
        },
        grid: {
            x: {
                lines: [
                    {value: '2015-06-01', text: 'DOE Scope Change', position: 'end'},
                    {value: '2015-07-02', text: 'DOE Scope Change', position: 'end'},
                    {value: '2015-07-07', text: 'DOE Scope Change', position: 'end'},
                    {value: '2015-07-14', text: 'Windows Server 2003 EOL', position: 'end'},
                    {value: '2015-09-09', text: 'DOE Scope Change', position: 'end'},
                    // {value: '2015-04-24', text: 'Report Agency', position: 'start'}
                ]
            },
            y: {
                show: is_printable_chart
            }
        }
    });
    
    var bod_chart2 = c3.generate({
        bindto: '#bod_chart2',
        data: {
            columns: [],
            mimeType: 'json',
            types: {
                age: 'bar',
            },
            groups: [],
            order: null,
            colors: {
                age: '#000000'
            },
            names: {
                age: 'vulnerability count',
            }
        },
        axis: {
            x: {
                label: {
                    text: 'Age (Days)',
                    position: 'center'
                },
            },
            y: {
                label: {
                    text: 'Vulnerability Count',
                    position: 'outer-middle'
                },
                min: 0,
                padding: {
                    bottom: 0
                }
            }
        },
        legend: {
            show: false
        },
        tooltip: {
            format: {
                title: function (d) {
                    if (d == 0) {return 'less than a day old';}
                    else if (d == 1) {return '1 day old';}
                    else return d + ' days old';
                },
            }
        },
        padding: {
            right: 20
        },
        regions: [
             {start: '0', end: '30', class:'blue'},
             {start: '30', end: '60', class:'yellow'},
             {start: '60', class:'red'}
        ],
        point: {
          show: false
        },
        grid: {
            x: {
                lines: [
                    {value: 30, text: '30 Days', position: 'end'},
                    {value: 60, text: '60 Days', position: 'end'},
                ]
            }
        }
    });
</script>
