drone_arch = "arm64"

# workaround to render locally since you cant pass repo.branch to the cli
def repo_branch(ctx):
    return getattr(ctx.repo, "branch", "main")


def version(ctx):
    # use git commit if this is not a tag event
    if ctx.build.event != "tag":
        return "git-{}".format(commit(ctx))

    return ctx.build.ref.removeprefix("refs/tags/")


def version_tag(ctx, arch):
    return "{}-{}".format(version(ctx), arch)


def commit(ctx):
    return ctx.build.commit[:7]


def build_env(ctx):
    return {
        "GIT_COMMIT": commit(ctx),
        "VERSION": version(ctx),
        "DRONE_ARCH": drone_arch,
    }


def new_pipeline(name, arch, **kwargs):
    pipeline = {
        "kind": "pipeline",
        "name": name,
        "platform": {
            "arch": arch,
        },
        "steps": [],
    }

    pipeline.update(kwargs)

    return pipeline


def pipeline_test(ctx):
    cache_volume = {"name": "cache", "temp": {}}
    cache_mount = {"name": "cache", "path": "/go"}

    # licensed-go image only supports amd64
    return new_pipeline(
        name="test",
        arch="amd64",
        trigger={"branch": repo_branch(ctx)},
        volumes=[cache_volume],
        workspace={"path": "/go/src/github.com/{}".format(ctx.repo.slug)},
        resources={
            "requests": {
                "cpu": 1000,
                "memory": "500MiB",
            },
        },
        steps=[
            {
                "commands": ["make test"],
                "image": "golangci/golangci-lint:v2.0",
                "name": "test",
                "volumes": [cache_mount],
            },
            {
                "commands": ["licensed cache", "licensed status"],
                "image": "public.ecr.aws/kanopy/licensed-go",
                "name": "license-check",
            },
        ],
    )


def main(ctx):
    pipelines = [pipeline_test(ctx)]

    return pipelines
