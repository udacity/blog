# BEND: Blog Project (P1)

Extension of the blog project students will build in the course.
[Live demo here](http://cs253-udacity-1203.appspot.com)!


---

### Local Setup

First, download the [Google App Engine SDK](https://cloud.google.com/appengine/docs/python)
and open the launcher application to create the symlinks you'll need to run `dev_appserver.py`
in the terminal.

Once that's all set, clone this repository:

```sh
$ git clone git@github.com:adarsh0806/blog.git
```

And simply run `dev_appserver.py .` from the main project folder. Go to http://localhost:8080
to see the blog app running and http://localhost:8000 for the admin console!

### Why This Version Doesn't Meet Specs

1. Users can like their own posts
2. Users can edit other people's posts
3. Code quality lacking: lots of pep8 errors, inconsistencies
4. Logout isn't handled properly; Cookies not deleted
5. Passwords stored in plain text, no hashing
