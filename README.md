# SmugMugUploadKeyCleaner

I am a long time customer of SmugMug and convinced the Boy Scout Troop I am webmaster of to use it as well.
This has worked out to be a positive experience. SmugMug allows upload links to be created so that parents/scouts
can upload their pictures. The downside is when/how to remove them over time.

Manual is always an option but I am a developer so I spent the time I could have been doing that to create this
python utility. This will scour through the root SmugMug albums and remove any upload keys that have been around
for too long.

It does not:

- Work recursively
- Allow to be pointed to 3rd party SmugMug accounts. It basically uses the API key's user and performs the action
  on that account


