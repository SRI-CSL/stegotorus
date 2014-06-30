(function($){
	TWP=window.TWP||{};
	TWP.Analytics=TWP.Analytics||{};
	TWP.Analytics.report=TWP.Analytics.report||{};
	TWP.Analytics.isMobile = TWP.Analytics.isMobile||function(){return $(window).width() < 768};
	TWP.Analytics.init = TWP.Analytics.init||function(config){
		config = config||{};
		TWP.Analytics.config = $.extend({
			suite:'production',
			service:{
				'omniture':true,'omnitureTest':false,'comscore':true,'chartbeat':true
			}
		},config);

		if (!! (TWP.Analytics.config.service.omniture || TWP.Analytics.config.service.omnitureTest) ) {
			TWP.Analytics.initOmniture();
		}
		if (!! TWP.Analytics.config.service.comscore ) {
			TWP.Analytics.initComScore();
		}
		if (!! TWP.Analytics.config.service.chartbeat ) {
			TWP.Analytics.initChartbeat();
		}
		TWP.Analytics.initReport();
	};

	TWP.Analytics.report.omniture={'name':'Omniture','on':false};
	TWP.Analytics.initOmniture = TWP.Analytics.initOmniture||function(config){
		var includeOmniture = true;
		switch(TWP.Analytics.config.suite){
			case "preproduction":
				// NOTE: For now, not using mobile suite.
				// window.s_account=(TWP.Analytics.isMobile())?"wpniwpmobileprodpp":"wpniwashpostcomEidospp";
				window.s_account="wpniwashpostcomEidospp";
				break;
			case "production":
				// NOTE: For now, not using mobile suite.
				// window.s_account=(TWP.Analytics.isMobile())?"wpniwpmobileprod":"wpniwashpostcom";
				window.s_account="wpniwashpostcom";
				break;
			default:
				includeOmniture = false;
		}

		if(includeOmniture){

			TWP.Analytics.report.omniture.on=true;
			TWP.Analytics.report.omniture.loaded=true;
			TWP.Analytics.report.omniture.suite=s_account;
			TWP.Analytics.report.omniture.testCode=!!TWP.Analytics.config.service.omnitureTest;

			var intervalCount = 0;
			var interval = setInterval(function(){
				var head = document.getElementsByTagName("head");
				if( !!head.length ){
					clearInterval(interval);

					var omnitureFile = (TWP.Analytics.config.service.omnitureTest) ? "omniture-test.js" : "omniture.js" ;
					var omnitureDomain = ".washingtonpost.com" ;
					if( "https:" == document.location.protocol ){
						omnitureDomain = "ssl" + omnitureDomain;
					} else {
						omnitureDomain = ( (TWP.Analytics.config.service.omnitureTest) ? "scoop" : "js" ) + omnitureDomain;
					}
	
					var sc = document.createElement("script");
					sc.type = "text/javascript";
					sc.src = ( ("https:" == document.location.protocol) ? "https://" : "http://") + omnitureDomain + "/wp-srv/analytics/"+omnitureFile;
					sc.onload = function(){
						TWP.Analytics.report.omniture.loaded=true;
						// TODO: Add methods at the TWP.Analytics namespace
						if (!!window.s){
							TWP.Analytics.uploadData = s.sendDataToOmniture;
							TWP.Analytics.triggerPageView = s.sendPageViewToOmniture;
							TWP.Analytics.triggerFullPageView = s.sendPageViewToOmnitureWithFullReset;
							// TODO: Only call this if wp_track_scrolling == true
							if (!!window.wp_track_scrolling) {
								TWP.Analytics.trackScrolling();
							}
						}
					};
					head[0].appendChild(sc);
	
				} else {
					intervalCount += 1;
					if(intervalCount > 20){
						clearInterval(interval);
					}
				}
			},500);
		} // if(includeOmniture)
			
	}; // TWP.Analytics.initOmniture

	TWP.Analytics.report.comscore={'name':'comScore','on':false};
	TWP.Analytics.initComScore = TWP.Analytics.initComScore||function(config){
		TWP.Analytics.report.comscore.on=true;
		TWP.Analytics.report.comscore.loaded=false;
		// NOTE: START Global variable
		_comscore = window._comscore || [];
		_comscore.push({ c1: "2", c2: "3005617" });
		// NOTE: END Global variable
		$(document).ready(function(){
			$.ajax(
				( ("https:" == document.location.protocol) ? "https://sb" : "http://b") + ".scorecardresearch.com/beacon.js",
				{dataType:"script",cache:true,success:function(){TWP.Analytics.report.comscore.loaded=true;}}
			);
		});
	}; // TWP.Analytics.initComScore

	TWP.Analytics.report.chartbeat={'name':'Chartbeat','on':false};
	TWP.Analytics.initChartbeat = TWP.Analytics.initChartbeat||function(config){
		TWP.Analytics.report.chartbeat.on=true;
		TWP.Analytics.report.chartbeat.loaded=false;
		// NOTE: START Global variable
		window._sf_startpt=(new Date()).getTime();
		_sf_async_config = window._sf_async_config||{};
		_sf_async_config=$.extend({
				uid:19624,
				domain:"washingtonpost.com",
				sections:(window.wp_section) ? wp_section : (window.TWP&&TWP.Data&&TWP.Data.Tracking) ? TWP.Data.Tracking.props.section : (window.thisNode) ? thisNode.split('/')[0] : "no category",
				path:document.location.pathname,
				title: (window.wp_meta_data&&wp_meta_data.isHomepage) ? "Homepage" : "",
				useCanonical:(window.wp_meta_data&&wp_meta_data.isErrorPage) ? false : true
		},_sf_async_config);
		// NOTE: END Global variable

		$(document).ready(function(){
			$.ajax(
				( ("https:" == document.location.protocol) ? "https://a248.e.akamai.net/chartbeat.download.akamai.com/102508/":"http://")+"static.chartbeat.com/js/chartbeat.js",
				{dataType:"script",cache:true,success:function(){TWP.Analytics.report.chartbeat.loaded=true;}}
			);
		});
	}; // TWP.Analytics.initChartbeat

	TWP.Analytics.trackScrolling = TWP.Analytics.trackScrolling||function(){

		var $w = $(window);
		function _screenFactor(){return TWP.Analytics.isMobile() ? 4 : 2 ;}
		function _pageHeight(){return $w.height()*_screenFactor();}
		function _currentPosition(){return $w.scrollTop();}
		function _currentPage(){return Math.floor( _currentPosition()/_pageHeight() )+1;}

		TWP.Analytics.scrollingConfig = {
			lastPosition:_currentPosition(),
			lastPage:_currentPage()
		}

		function _checkPosition(pos,pg){
			if(
				pos == _currentPosition()
				&& pg != TWP.Analytics.scrollingConfig.lastPage
				&& Math.abs(TWP.Analytics.scrollingConfig.lastPosition - pos) >= _pageHeight()
			){
				TWP.Analytics.scrollingConfig.lastPosition = pos;
				TWP.Analytics.scrollingConfig.lastPage = pg;
				// NOTE: START Global variable
				wp_page_num = "page_"+pg;
				// NOTE: END Global variable
				TWP.Analytics.triggerPageView({
					prop3:wp_content_type,
					eVar17:wp_content_type,
					prop14:wp_page_num
				});
			}
		}

		$w.scroll(function(){
			var pos = _currentPosition();
			var pg = _currentPage();
			// closure voodoo here
			setTimeout((function(arg1,arg2){
				return function(){
					_checkPosition(arg1,arg2);
				};
			}(pos,pg)),500);
		});

	} // TWP.Analytics.trackScrolling

	TWP.Analytics.initReport = TWP.Analytics.initReport||function(){
		if( !!document.location.search.match(/debugAnalytics/) ){
			$(document).ready(function(){
				var debugIntervalCount = 0;
				var debugInterval = setInterval(function(){
					debugIntervalCount += 1;
	
					var services = ['omniture','comscore','chartbeat'];
					$( '#debugAnalytics' ).remove();
	
					var data = "";
					for(var i=0;i < services.length;i++){
						var service = services[i];
						if(!! TWP.Analytics.report[service] ){
							var report = TWP.Analytics.report[service];
							data+='<h3 style="text-align:left;"><b>'+report.name+':</b> ';
							for(var p in report){
								if (p != 'name') data += p+':'+report[p]+'; ';
							}
							if(service=='omniture'){
								if(!!window.wp_page_num){
									data += 'page_num: '+wp_page_num+'; ';
								}
							}
							data+="</h3>";
						}
					}
	
					$('body').children(':first').before(
						$('<div id="debugAnalytics">'+data+'</div>')
					);
	
					if( debugIntervalCount > 60){
						clearInterval(debugInterval);
						$( '#debugAnalytics' ).prepend('<h3 style="text-align:left;color:#C00;">No longer updating.</h3>');
					}
				},1000);
			});
		}
	}; // TWP.Analytics.initReport

})(jQuery);