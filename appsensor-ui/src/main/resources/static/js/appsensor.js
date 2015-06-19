$(function() {
	var panels = $( "#dashboard-left-column, #dashboard-right-column" );
	
	panels.sortable({
      connectWith: ".connectedSortable",
      update: function(event, ui) {
          $('.ui-state-default', panels).each(function(index, elem) {
               var listItem = $(elem),
                   newIndex = listItem.index();
//               console.log(listItem.prop('id') + ' is at ' + newIndex + ' in ' + listItem.parent().prop('id'));
               // Persist the new indices.
          });
      }
    }).disableSelection();
  });
