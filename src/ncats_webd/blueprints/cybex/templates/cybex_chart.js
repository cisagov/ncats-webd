<script type="text/javascript"  charset="utf-8">

    socket.on('connect', function() {
        console.log('connected (cybex)');
        socket.emit('join', {'room':'cybex'});
        socket.emit('cybex_latest');
    });

    socket.on('cybex_data_push', function(msg) {
        console.log('received new cybex data');
        cybex_chart1.load({json:JSON.parse(msg.cybex_chart1)});
        cybex_chart2.load({json:JSON.parse(msg.cybex_chart2)});
        cybex_chart3.load({json:JSON.parse(msg.cybex_chart3)});
        cybex_chart4.load({json:JSON.parse(msg.cybex_chart4)});
		console.log(msg);
    })

    if (typeof is_printable_chart === 'undefined') {
        var is_printable_chart = false;
    }

    var cybex_chart1 = c3.generate({
        bindto: '#cybex_chart1',
        data: {
            columns: [],
            mimeType: 'json',
            x: 'x',
            types: {
                young: 'area',
                old: 'area',
                total: 'line'
            },
            groups: [['young','old']],
            order: null,
            colors: {
                young: '#0099cc',
                old: '#cc0000',
                total: '#777777'
            },
            names: {
                young: '< 30 days',
                old: '> 30 days',
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
                // min: 0,
				// max: 1400,
                padding: {
                    bottom: 0
                }
            }
        },
        padding: {
            right: 25
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
                    //{value: '2015-05-21', text: 'BOD 15-01 Start', position: 'end'},
                ]
            },
            y: {
                show: is_printable_chart
            }
        }
    });

    var cybex_chart2 = c3.generate({
        bindto: '#cybex_chart2',
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
            },
        },
        axis: {
            x: {
				type: 'category',
                label: {
                    text: 'Age (Days)',
                    position: 'center'
                },
				tick: {
					//count: 10,
					values: [0, 20, 40, 60, 80, 100, 120, 140, 160, 180],
					fit: false,
					centered: true,
					format: function (d) {
						return (d == 180) ? (d+'+') : d;
					},
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
                },
				tick: {
					format: function (d) {
						return (parseInt(d) == d) ? d : null;
					}
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
                    else if (d == 180) {return '180+ days old';}
					else if (d > 180) {return null;}
					else return d + ' days old';
                },
            }
        },
        padding: {
            right: 18
        },
        regions: [
             {start: '0', end: '7', class:'cybex-age1', opacity:0.4},
             {start: '7', end: '14', class:'cybex-age2', opacity:0.4},
			 {start: '14', end: '21', class:'cybex-age3', opacity:0.4},
			 {start: '21', end: '30', class:'cybex-age4', opacity:0.4},
			 {start: '30', end: '90', class:'cybex-age5', opacity:0.4},
             {start: '90', class:'cybex-age6', opacity:0.3}
        ],
        point: {
          show: false
        },
        grid: {
            x: {
                lines: [
                    {value: 7, text: '7 Days', position: 'end'},
                    {value: 14, text: '14 Days', position: 'end'},
                    {value: 21, text: '21 Days', position: 'end'},
                    {value: 30, text: '30 Days', position: 'end'},
                    {value: 90, text: '90 Days', position: 'end'},
                ]
            }
        }
    });

    var cybex_chart3 = c3.generate({
        bindto: '#cybex_chart3',
        data: {
            columns: [],
            mimeType: 'json',
            x: 'x',
            types: {
                young: 'area',
                old: 'area',
                total: 'line'
            },
            groups: [['young','old']],
            order: null,
            colors: {
                young: '#0099cc',
                old: '#cc0000',
                total: '#777777'
            },
            names: {
                young: '< 30 days',
                old: '> 30 days',
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
                // min: 0,
				// max: 1400,
                padding: {
                    bottom: 0
                }
            }
        },
        padding: {
            right: 25
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
                    //{value: '2015-05-21', text: 'BOD 15-01 Start', position: 'end'},
                ]
            },
            y: {
                show: is_printable_chart
            }
        }
    });

    var cybex_chart4 = c3.generate({
        bindto: '#cybex_chart4',
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
				type: 'category',
                label: {
                    text: 'Age (Days)',
                    position: 'center'
                },
				tick: {
					//count: 10,
					values: [0, 40, 80, 120, 160, 200, 240, 280, 320, 360],
					fit: false,
					centered: true,
					format: function (d) {
						return (d == 360) ? (d+'+') : d;
					}
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
                    else if (d == 360) {return '360+ days old';}
					else if (d > 360) {return null;}
					else return d + ' days old';
                },
            }
        },
        padding: {
            right: 20
        },
        regions: [
             {start: '0', end: '14', class:'cybex-age1', opacity:0.4},
             {start: '14', end: '28', class:'cybex-age2', opacity:0.4},
			 {start: '28', end: '42', class:'cybex-age3', opacity:0.4},
			 {start: '42', end: '60', class:'cybex-age4', opacity:0.4},
			 {start: '60', end: '180', class:'cybex-age5', opacity:0.4},
             {start: '180', class:'cybex-age6', opacity:0.3}
        ],
        point: {
          show: false
        },
        grid: {
            x: {
                lines: [
                    {value: 14, text: '14 Days', position: 'end'},
                    {value: 28, text: '28 Days', position: 'end'},
                    {value: 42, text: '42 Days', position: 'end'},
                    {value: 60, text: '60 Days', position: 'end'},
                    {value: 180, text: '180 Days', position: 'end'},
                ]
            }
        }
    });
</script>
