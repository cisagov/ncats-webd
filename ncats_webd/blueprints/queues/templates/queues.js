<script type="text/javascript"  charset="utf-8">
    socket.on('connect', function() {
        console.log('connected (queues)');
        socket.emit('join', {'room':'queues'});
        socket.emit('queues_latest');
    });

    socket.on('disconnect', function() {
        console.log('disconnected (queues)');
    });

    socket.on('queues_data_push', function(msg) {
        console.log('new queue data');
        update_all_charts(JSON.parse(msg.data));
    })
    
    function make_chart(chart_id, colors) {
        var color_ramp = d3.scale.linear().domain([-16,0]).range(colors);
        var chart = c3.generate({
            bindto: chart_id,
            data: {
                columns: [],
                type : 'donut',
                order: function (d1, d2) { console.log(d1,d2); return d1 > d2; },
                color: function (color, d) {
                    // d will be 'id' when called for legends
                    return color_ramp(d)
                }
            },
            donut: {
                title: '0',
                label: {
                    format: function (value, ratio, id) {
                        return (id);
                    },
                    threshold: 0.04
                },
                width: 10
            },
            legend: {
                'hide': true
            },
            tooltip: {
                format: {
                    value: function (value, ratio, id, index) { return d3.format(',')(value) + " (" + d3.format('%')(ratio) + ")"; }
                }
            },
            transition: {
                duration: 3000
            },
        });
        chart.legend.hide();
        // replace title with d3 enabled title
        main = chart.internal.main
        main.selectAll('.c3-chart-arcs-title').remove();
        arcs = main.select('.c3-chart-arcs')
        arcs.selectAll('text').data([0]).enter().append('text')
            .attr('class', 'c3-chart-arcs-title')
            .style('text-anchor', 'middle')
            .style('opacity', 1)
            .text(0);
        return chart;
    }

    var ns1_waiting = make_chart('#ns1_waiting', colorbrewer.Reds[3].slice().reverse());
    var ns1_running = make_chart('#ns1_running', colorbrewer.Reds[3].slice().reverse());
    var ns2_waiting = make_chart('#ns2_waiting', colorbrewer.Oranges[3].slice().reverse());
    var ns2_running = make_chart('#ns2_running', colorbrewer.Oranges[3].slice().reverse());
    var ps_waiting = make_chart('#ps_waiting', colorbrewer.Blues[3].slice().reverse());
    var ps_running = make_chart('#ps_running', colorbrewer.Blues[3].slice().reverse());
    var vs_waiting = make_chart('#vs_waiting', colorbrewer.Greens[3].slice().reverse());
    var vs_running = make_chart('#vs_running', colorbrewer.Greens[3].slice().reverse());

    function update_chart(chart, column_data, do_tween) {
        if (do_tween) {
            tween_duration = 5000;
        } else {
            tween_duration = 0;
        }
        var sum = column_data.reduce(function(a, b) { return a + b[1]; }, 0);
        var svg_text = chart.internal.main.selectAll('.c3-chart-arcs-title');
        var previous_datum = svg_text.datum();
        svg_text.datum(sum).transition().duration(tween_duration)
        .tween('text', function(d) {
            var i = d3.interpolateRound(previous_datum, d);
            return function(t) {
                this.textContent = d3.format(',')(i(t));
            };
        });
        chart.load({columns:column_data});
    }

	function update_all_charts(json_data, do_tween) {
        var do_tween = (typeof do_tween === 'undefined') ? true : do_tween;
        update_chart(ns1_waiting, json_data.ns1_waiting, do_tween);
        update_chart(ns1_running, json_data.ns1_running, do_tween);
        update_chart(ns2_waiting, json_data.ns2_waiting, do_tween);
        update_chart(ns2_running, json_data.ns2_running, do_tween);
        update_chart(ps_waiting, json_data.ps_waiting, do_tween);
        update_chart(ps_running, json_data.ps_running, do_tween);
        update_chart(vs_waiting, json_data.vs_waiting, do_tween);
        update_chart(vs_running, json_data.vs_running, do_tween);
    }

    //initial load
    //d3.json("?j").get(function(error, data) { update_all_charts(data, false)}); 
</script>