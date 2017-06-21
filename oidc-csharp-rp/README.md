This document describes how to setup the provided Csharp code
(in the directory ``csharp_skeleton/``) in Visual Studio.


# Prerequisites

* Visual Studio 2013 (or more recent)
* DotNetOpenAuth installed (as per referenced project where all code is available)


# Setup using Visual Studio

1. Import the project in Visual Studio and install prerequisites:
  1. Open ``the csharp_skeleton.sln file``
  2. Install the DotNetOpenAuth dependency: select TOOLS->NuGet Package Manager->Package Manager Console and then
  execute the command ``Install-Package DotNetOpenAuth.OpenId.RelyingParty -Version 4.3.4.13329``.

1. Test that the project runs:
  1. Specify the path to the directory containing all necessary files (``client.json``, ``index.html``, etc.) in ``Client::ROOT_PATH`` (in ``csharp_skeleton/Client.cs``).
  1. Run the project.
  1. The application should output something like:

         ```
         A simple webserver. Press a key to quit.
         Webserver running...
         ```

  1. Verify the Relying Party (RP) is running at [http://localhost:8090](http://localhost:8090)

1. Start adding to the skeleton code:
  1. The missing parts are marked with ``TODO`` in
       ``csharp_skeleton/Client.cs``.
  1. Read the [Csharp Cookbook](doc/doc.md) for more information
       about how to use the DotNetOpenAuth library.
  1. Make sure to delete cookies and cached data in the browser while
       testing to avoid strange results (e.g. due to the browser caching
       redirects, etc.).
