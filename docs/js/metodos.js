$(document).ready(function() {

	//  Show nav + overlay-content
	$('.menu-open').click(function() {
		if($(this).hasClass('clic')){
			closeNavigation();
		}else{
			openNavigation();
		}
		$(this).toggleClass('clic');
	});

	function openNavigation(){
		$('.navigation').fadeIn();
	}

	function closeNavigation(){
		$('.navigation').fadeOut();
	}

	// Header fixed
	$(function(){
		var shrinkHeader = 80;
		$(window).scroll(function() {
			var scroll = getCurrentScroll();
			if ( scroll >= shrinkHeader ) {
				$('.site-header').addClass('small-header');
			}else {
				$('.site-header').removeClass('small-header');
			}
		});
	});

	function getCurrentScroll() {
		return window.pageYOffset || document.documentElement.scrollTop;
	}

});
