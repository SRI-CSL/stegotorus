(function(){
	
	/*********************************************************************
	*SET REDIRECT CONFIG HERE.  
	*	   Sites can be any value.  For Methode, sites match site-identity.  
	*	   For each site, set value as appropriate.  
	*			true - redirect to mobile
	*			false - do nothing
	*/	 
	var config={sites:
		{
		'prodportal-A':false,
		'prodportal-B':false,
		'deveditorial':false,
		'qaeditorial':false,
		'prodeditorial':false,
		'wordpress-dev':false,
		'wordpress':false
		}};
	
	/**********************************************************************/

	/**TO USE THIS FILE***************************************************
	*  1.  Update redirect config
	*  2.  Include this file at top of <head>
	*  3.  execute function TWP.Util.redirectMobile(site);
	*
	*/

	/**SAMPLE************************************************************
	*<head
	*<s cript type="text/javascript" src="http://wp-eng-static.washingtonpost.com/util-redirect.js"></script>
	*<s cript type="text/javascript">try {TWP.Util.redirect.redirectMobile("deveditorial");}catch(e){};</script>
	*</head
	*/

	/****DO NOT CHANGE ANYTHING BELOW THIS LINE *****/
	/****SERIOUSLY!**********************************/
	
	TWP = window.TWP || {};
	TWP.Util = TWP.Util || {};
	TWP.Util.redirect = {
			redirectMobile: function (currentSite) {	
				if (currentSite && config.sites[currentSite] === true) {
					window.location=window.location.toString().replace(/.*\/\/[^\/]+/, "http://m.washingtonpost.com");
				}
			},
			config: config
	}		
})();
