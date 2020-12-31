<script type='text/javascript'  charset='utf-8'>

var MAX_TICKET_LIST_SIZE = 20;

socket.on('connect', function() {
    console.log('connected (ticket_log)');
    socket.emit('join', {'room':'ticket_log'});
});

socket.on('disconnect', function() {
    console.log('disconnected (ticket_log)');
});

socket.on('new_tickets', function(msg) {
    console.log('new ticket data', msg.length);
    update_ticket_log(msg);
})

socket.on('historic_tickets', function(msg) {
    console.log('historic ticket data', msg.length);
    update_ticket_log(msg);
})

function update_ticket_log(tickets) {
    //BIND
    var lis = d3.select('#ticket_log').selectAll('li')
        .data(tickets, function(d) { return d._id; });
    //ENTER
    var li = lis.enter()
        .append('li').append('div').attr('class','row')
    
    li.append('div')
        .attr('class', 'small-2 columns')
            .append('i')
            .attr('class', 'fi-burst-new size-72')
            .text(function(d){return d.events[0].action;})
    li.append('div')
        .attr('class', 'small-2 columns')
            .append('i')
            .attr('class', 'fi-alert size-72')
            .text(function(d){return d.details.severity;})
    li.append('div')
        .attr('class', 'small-2 columns')
            .text(function(d){return d.owner;})
    li.append('div')
        .attr('class', 'small-6 columns')
            .text(function(d){return d.details.name;})
    //EXIT
    //lis.exit().remove();
    
    //trim items from top of log
    lis = d3.select('#ticket_log').selectAll('li');
    var overage = lis[0].length - MAX_TICKET_LIST_SIZE;
    if (overage > 0) {
        var exiting = d3.selectAll(lis[0].slice(0, overage));
        exiting
            .attr('class', 'exit')
        .transition()
            .duration(5000)
            .style('line-height', '0px')
            .style('color', '#fff')
        .remove();
    }
}

socket.emit('history', MAX_TICKET_LIST_SIZE);
</script>
