/**
 * Created by murli on 2/3/2017.
 */

var userList = $('.mobile-user-list');
var userSearch = $('#user-search');

userSearch.keyup(function() {
  var userVal = $(this).val();
  userList.each(function(index){
  var name = $(this).children('.user-name').text();
  if (name.indexOf(userVal) === -1 ) {
    $(this).css("display", "none");
  } else {
    $(this).css("display", "");
  }
});
});



