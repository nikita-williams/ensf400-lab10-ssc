# ENSF400 Lab 10: Software Supply Chain

## Objectives
This lab demonstrates some of the tools and formats which are used to manage the software supply chain
in terms of security and licensing. 
We will use [Syft](https://github.com/anchore/syft), 
[Grype](https://github.com/anchore/grype),
[vexctl](https://github.com/openvex/vexctl), and 
[FOSSology](https://www.fossology.org/). 

## Environment
This lab will use Docker images on your local system. It is expected that `docker` and
`git` are already installed from earlier labs.

### Setup
It is recommended that you pull the FOSSology image before working on the rest of the lab, as
it will take some time to download the full image. You can let it download in the background
while you read the rest of the lab.

```
docker pull fossology/fossology:4.4.0
```

This lab will create some output files. It is recommended that you run the commands from a location 
you can easily keep tidy, such as Downloads.

### Note for Windows users
If you are running on Windows, you will need to use WSL in order for the redirection of output
to a file to work properly. In Powershell, the line endings will be incorrect and you will be
unable to reuse the SBoM file in Grype. Alternately, you can complete tasks 1-3 from [within a 
Linux container](https://medium.com/@shivam77kushwah/docker-inside-docker-e0483c51cc2c).

## Task 1 - Creating an SBoM
We will use Syft to generate an SBoM from the Alpine container image. We want to generate the SBoM using 
the SPDX standard, in the JSON data format, and store the output in a file. We will use this output later.
You may opt to redirect the output for other commands as well. 

Because we are using this container only once, we will clean it up after completion with the `--rm` command.

```
docker run --rm anchore/syft:v1.0.1 scan alpine:3.19.1 -o spdx-json > alpine.spdx.json
```

To read the JSON file, you may find it helpful to load it in your IDE and apply formatting.

The SBoM that we generated only includes software which is part of the container. We can also look through
all the container layers with `--scope all-layers`. This time, we will output in CycloneDX format.

```
docker run --rm anchore/syft:v1.0.1 scan alpine:3.19.1 -o cyclonedx --scope all-layers
```

Syft can generate from a variety of sources including images, files, directories, and archives. 
It will attempt to determine the source based on the provided input. We can also provide assistance
with the `--from` argument. 

We do not even have to have the container installed. In this example, we will pull from the DockerHub
registry. We will put the output to the screen, in the Syft text format, which is human-readable.

```
docker run --rm anchore/syft:v1.0.1 scan --from registry snyk/snyk:alpine -o syft-text
```

Now, let's see Syft work on a directory. We will clone the Syft repository and then mount the directory
where it was cloned in order to learn more about Syft itself. We will not generate an SBoM but simply
generate a list of dependencies.

In the example, we are using longer names to allow for clearer distinction between the
Syft image, the volume mount point, and the cloned repository. You can use other names as you see fit.

```
git clone https://github.com/anchore/syft my-syft-clone
docker run --rm -v ${PWD}:/download-data anchore/syft:v1.0.1 scan /download-data/my-syft-clone
```

## Task 2 - Examining vulnerabilities

We will use Grype to look for vulnerabilities. Grype has to pull down and create a database of vulnerabilities,
so the initial run may take some time. Because we will run all the instances of Grype during the course of this
lab, we do not need to worry about updates to the database and can cache it to save time. We do this with the
`GRYPE_DB_CACHE_DIR` variable which is linked to a volume. In subsequent runs we specify
`GRYPE_DB_AUTO_UPDATE` as false.

The use of the `-it` flag is optional, but it will provide information about the process. If you have
chosen to redirect the output to a file, you should probably not use the flag as the progress report
will be added to the file.

First, let's look for vulnerabilities in Syft:

```
docker run --rm -it -e GRYPE_DB_CACHE_DIR=/host -v ${PWD}:/host anchore/grype:v0.74.7 anchore/syft:v1.0.1
```

As in Syft, we can include all layers with the argument `--scope all-layers`:

```
docker run --rm -it -e GRYPE_DB_CACHE_DIR=/host -v ${PWD}:/host -e GRYPE_DB_AUTO_UPDATE=false anchore/grype:v0.74.7 justinjustin/poc --scope all-layers
```

The results are quite different! The image we just examined was created to allow people to safely examine the log4j 
vulnerability and look for ways to mitigate it. There are several expected vulnerabilities in the image, including
the critical log4j vulnerabilities.

## Task 3 - Creating a VEX and using the VEX and SBoM in vulnerability scanning

Let's take a quick look at a package with just a few vulnerabilities:

```
docker run --rm -it -e GRYPE_DB_CACHE_DIR=/host -v ${PWD}:/host -e GRYPE_DB_AUTO_UPDATE=false -v ${PWD}:/data anchore/grype:v0.74.7 alpine:3.16
```

We will now use `vexctl` to generate a VEX file allowing us to overlook a vulnerability we expected
to find. Notice is that this container is published on GitHub rather than DockerHub so we must specify
`ghcr.io`.

```
docker run --rm -it -v ${PWD}:/data ghcr.io/openvex/vexctl:v0.2.6 create --vuln="CVE-2024-0727" --status="not_affected" --justification="vulnerable_code_cannot_be_controlled_by_adversary" --product="pkg:oci/alpine" --file /data/alpine-3.16-img.json
```
If we run the container without arguments we can see the available commands. Using an incorrect justification will
show the list of available justifications.

If we apply the VEX document to our scan, the vulnerability we marked as not affected should be eliminated.

```
docker run --rm -it -e GRYPE_DB_CACHE_DIR=/host -v ${PWD}:/host -e GRYPE_DB_AUTO_UPDATE=false -v ${PWD}:/data anchore/grype:v0.74.7 --vex /data/alpine-3.16-img.json alpine:3.16
```

Next, let's look at using the SBoM we generated earlier as input to Grype. In this example, the SBoM which was
generated was stored in the current directory (PWD). You will need to specify the correct location of the file on your system.

If an SBOM does not include any Common Platform Enumeration (CPE) information, it is possible to generate these based on package information using the `--add-cpes-if-none` flag. CPE, like PURL, is a structured naming scheme.

```
docker run --rm -it -e GRYPE_DB_CACHE_DIR=/host -v ${PWD}:/host -e GRYPE_DB_AUTO_UPDATE=false -v ${PWD}:/data anchore/grype:v0.74.7 --add-cpes-if-none sbom:/data/alpine.spdx.json
```

## Task 4 - Scan for licenses

To scan for licenses, we will use Nomos, which is part of FOSSology. You may use a different port if you prefer.

```
docker run --rm -p 8081:80 fossology/fossology:4.4.0
```

You can access the web page at http://localhost:8081/repo - to log in, use the username `fossy` and the password `fossy`.

Because license scanning is time-consuming, we will analyse a small repository. There are some issues with using
the URL uploader, so we will upload from a zip file.

```
git clone https://github.com/growlf/toolbox toolbox
zip -r toolbox.zip toolbox
```

Go to `Upload > From File` and select your zip file. Check the box for Nomos in section 7, then click Upload. Progress of the scanning can be seen under the `Jobs` tab. When the scanning is complete, go to the `Browse` tab and click on the scan (`toolbox.zip`).

FOSSology is intended to allow licenses to be marked as appropriate or inappropriate for use in an organization.
We are only going to use it to look at inconsistencies. Most organizations would probably use a program such
as SonarQube alongside the CI/CD pipeline to constantly check for the introduction of licenses.

You should be able to see that the `src` folder and the `LICENSE` file both refer to licenses. You can examine all
files with licenses and `Dockerfile` to understand the context in which the different licenses are used. With this information and with reference to the lecture material, you should be able to answer the related question.

## Have your work checked by a TA

Each member of the group should be able to answer all of the following questions. The TA will ask each 
person one question selected at random, and the student must be able to answer the question to get credit for 
the lab. You may discuss the questions within your group and ask for help from a TA prior to having your work marked in order to prepare, but you may *not* discuss the question or answer with friends or teammates during marking.

- Q1: What are the implications of the Toolbox project being GPLv3 licensed and having a sub-component which is MIT licensed? Consider (a) the effect of having GPLv3 as the repository license and MIT as an in-code license, and (b) what we can understand about the licenses affecting the container based on the licenses expressed in `zsh-in-docker.sh` and `LICENSE` and the context in which these files are used (other container layers and includes do not need to be considered).
- Q2: (a) What does each part of the command `docker run --rm -it -e GRYPE_DB_CACHE_DIR=/host -v ${PWD}:/host -e GRYPE_DB_AUTO_UPDATE=false -v ${PWD}:/data anchore/grype sbom:/data/alpine.spdx.json` do? (b) How could you simplify the command while retaining all functionality?
- Q3: (a) What are the allowed justifications for marking a vulnerability as `not_affected` when creating a VEX file? (b) What command would you use to mark vulnerability `CVE-2022-0563` as `fixed`? Explain each part of the command.
- Q4: (a) Which license is declared for the BusyBox package in the Alpine image, according to the output collected in `alpine.spdx.json`? Which license is declared by the musl package? (b) Are there any licensing concerns with including both these packages in this container? Why or why not?
- Q5: (a) What command would you use to create an SBoM for the FOSSology 4.4.0 image in CycloneDX XML format, saving the result to a file? Explain each part of the command. (b) What command would you use to provide the resulting SBoM to Grype *without* creating or using a cache of the vulnerabilities database? 

