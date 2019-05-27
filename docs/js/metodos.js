$(document).ready(function () {

	//  Show nav + overlay-content
	$('.menu-open').click(function () {
		if ($(this).hasClass('clic')) {
			closeNavigation();
		} else {
			openNavigation();
		}
		$(this).toggleClass('clic');
	});

	// $('.overlay-content').click(function() {
	//     closeNavigation();
	// });

	// $('.menu-close').click(function() {
	// 	closeNav();
	// });

	function openNavigation() {
		// $('body').addClass('nav-fixed');
		$('.navigation').fadeIn();
		// $('.js-overlay').fadeIn();
	}

	function closeNavigation() {
		// $('body').removeClass('nav-fixed');
		$('.navigation').fadeOut();
		// $('.js-overlay').fadeOut();
	}

	// Header fixed
	$(function () {
		var shrinkHeader = 80;
		$(window).scroll(function () {
			var scroll = getCurrentScroll();
			if (scroll >= shrinkHeader) {
				$('.site-header').addClass('small-header');
			} else {
				$('.site-header').removeClass('small-header');
			}
		});
	});

	function getCurrentScroll() {
		return window.pageYOffset || document.documentElement.scrollTop;
	}

	$(document).ready(function() { var pathname = window.location.pathname;
		pathname = pathname.replace('/FORT-validator/doc', '.');
		pathname = pathname.replace('/FORT-validator', '.');

		//get the path of current page
		$('.site-nav > ul > li > a[href="'+pathname+'"]').addClass('active-item');
	})


});
