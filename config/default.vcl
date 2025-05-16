vcl 4.0;

# Borrowed from mediawiki.org/wiki/Manual:Varnish_caching
# and modified for Canasta

# There are two goals here:
# a) In an overload situation, prioritize logged in users
# b) Limit max concurrency. Try to prevent the situation where a crawler
#    hits a large number of uncached pages all at once, saturating CPU/Memory
#    causing everything to slow to a halt. Better to delay and do a little at
#    a time so progress is made, instead of all at once where the server becomes
#    saturated and threads start piling up until timeouts are hit.

# The way this works is by setting a max number of in-flight requests for certain
# request types. Note that any cached response is returned immediately. Also if
# different people are requesting the same page they are counted as only 1. The
# idea is that there is a max amount of resources that logged out users can use so
# they should not be able to overwhelm the server.

# Note .wait_limit and .wait_timeout are new in varnish 7.6. Remove if using earlier varnish.

# This is assuming a small wiki. If your wiki is really busy and normal logged out (non-malicious) users
# are getting 503's, increase max_connections in anonview and anonspecial.

# Logged in, api, load.php, images, anything else
backend default {
    .host = "web";
    .port = "80";
    .first_byte_timeout = 120s; 
    .connect_timeout = 30s; 
    .between_bytes_timeout = 120s;
}

# Normal page view by an anon
backend anonview {
	.host = "web";
	.port = "80";
	.first_byte_timeout = 120s;
	.connect_timeout = 30s;
	.between_bytes_timeout = 120s;
	.max_connections = 5;  # Set to 10 for a high traffic wiki. Set to 3 if wiki overwhelmed
	.wait_limit = 50; # Set to 100 for busy wiki.
	.wait_timeout = 60s;
}

# A special page view or ?action=history, etc.
backend anonspecial {
	.host = "web";
	.port = "80";
	.first_byte_timeout = 120s;
	.connect_timeout = 30s;
	.between_bytes_timeout = 120s;
	.max_connections = 2; # Set to 5 for a high traffic wiki.
	.wait_limit = 20; # Set to 100 for a high traffic wiki.
	.wait_timeout = 30s;
}

# Stuff that is maybe evil.
backend sus {
	.host = "web";
	.port = "80";
	.first_byte_timeout = 120s;
	.connect_timeout = 30s;
	.between_bytes_timeout = 120s;
	.max_connections = 1;
	.wait_limit = 10;
	.wait_timeout = 30s;
}

acl purge {
    "web";
}

# vcl_recv is called whenever a request is received 
sub vcl_recv {
    # Serve objects up to 2 minutes past their expiry if the backend
    # is slow to respond.
    # set req.grace = 120s;

    set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;

    set req.backend_hint= default;

    # This uses the ACL action called "purge". Basically if a request to
    # PURGE the cache comes from anywhere other than localhost, ignore it.
    if (req.method == "PURGE") {
        if (!client.ip ~ purge) {
            return (synth(405, "Not allowed."));
        } else {
            return (purge);
        }
    }

    # Pass sitemaps
    if (req.url ~ "\.xml(\.gz)?$") {
        return (pass);
    }

    # Pass images
    if (req.url ~ "/w/images/") {
        return(pass);
    }

    # Pass parsoid
    if (req.url ~ "/w/rest.php/") {
        return(pass);
    }

    # Pass API
    if (req.url ~ "/w/api.php") {
        return(pass);
    }

    call mobile_detect;

    # Pass requests from logged-in users directly.
    # Only detect cookies with "session" and "Token" in file name, otherwise nothing get cached.
    if (req.http.Authorization || req.http.Cookie ~ "([sS]ession|Token)=") {
        return (pass);
    } /* Not cacheable by default */

    # logged out normal view
    if (req.url ~ "/wiki/") {
        set req.backend_hint = anonview;
    }
    # We are assuming english lang here
    if (
        ( req.url ~ "/w/index\.php" || req.url ~ "/wiki/Special:" || req.url ~ "[?&]action=" )
        && req.url !~ "Special:UserLogin"
    ) {
        set req.backend_hint = anonspecial;
    }

    # Put suspicious looking user-agents in the slow lane.
    # This likely has some false positives, so don't block entirely.
    # An additional idea might be to use vthrottle to put IP addresses here if they
    # request too much too fast.
    if (
        ( req.http.User-Agent !~ "Chrome/[1-9][3-9][0-9]" &&
        req.http.User-Agent !~ "Firefox/[1-9][0-9][0-9]" &&
        req.http.User-Agent !~ "Safari/[5-9][0-9][0-9]" ) ||
        req.http.User-Agent ~ "Windows NT ([0-5]\.|6\.[01])" || 
        req.http.User-Agent ~ "Mac OS X 10_[0-5]_" 
    ) {
        set req.backend_hint = sus;
    }


    # Pass anything other than GET and HEAD directly.
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    } /* We only deal with GET and HEAD by default */

    # Force lookup if the request is a no-cache request from the client.
    if (req.http.Cache-Control ~ "no-cache") {
        ban(req.url);
    }

    # normalize Accept-Encoding to reduce vary
    if (req.http.Accept-Encoding) {
        if (req.http.User-Agent ~ "MSIE 6") {
        unset req.http.Accept-Encoding;
        } elsif (req.http.Accept-Encoding ~ "gzip") {
        set req.http.Accept-Encoding = "gzip";
        } elsif (req.http.Accept-Encoding ~ "deflate") {
        set req.http.Accept-Encoding = "deflate";
        } else {
        unset req.http.Accept-Encoding;
        }
    }

    return (hash);
}

sub vcl_pipe {
        # Note that only the first request to the backend will have
        # X-Forwarded-For set.  If you use X-Forwarded-For and want to
        # have it set for all requests, make sure to have:
        # set req.http.connection = "close";
 
        # This is otherwise not necessary if you do not do any request rewriting.
 
        set req.http.connection = "close";
}

# Called if the cache has a copy of the page.
sub vcl_hit {
        if (!obj.ttl > 0s) {
            return (pass);
        }
}

# Called after a document has been successfully retrieved from the backend.
sub vcl_backend_response {
        # Don't cache 50x responses
        if (beresp.status == 500 || beresp.status == 502 || beresp.status == 503 || beresp.status == 504) {
            set beresp.uncacheable = true;
            return (deliver);
        }

        if (!beresp.ttl > 0s) {
          set beresp.uncacheable = true;
          return (deliver);
        }
 
        if (beresp.http.Set-Cookie) {
          set beresp.uncacheable = true;
          return (deliver);
        }
 
        if (beresp.http.Authorization && !beresp.http.Cache-Control ~ "public") {
          set beresp.uncacheable = true;
          return (deliver);
        }

        return (deliver);
}

sub mobile_detect {
    set req.http.X-Device = "pc";

    if ( (req.http.User-Agent ~ "(?i)(mobi|240x240|240x320|320x320|alcatel|android|audiovox|bada|benq|blackberry|cdm-|compal-|docomo|ericsson|hiptop|htc[-_]|huawei|ipod|kddi-|kindle|meego|midp|mitsu|mmp\/|mot-|motor|ngm_|nintendo|opera.m|palm|panasonic|philips|phone|playstation|portalmmm|sagem-|samsung|sanyo|sec-|semc-browser|sendo|sharp|silk|softbank|symbian|teleca|up.browser|vodafone|webos)"
            || req.http.User-Agent ~ "^(?i)(lge?|sie|nec|sgh|pg)-" || req.http.Accept ~ "vnd.wap.wml")
        && req.http.User-Agent !~ "(SMART-TV.*SamsungBrowser)" )
    {
        set req.http.X-Device = "mobile";
    }
}
