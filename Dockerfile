#
# Copyright 2020 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

FROM registry.access.redhat.com/ubi8/ubi-minimal:8.1

RUN mkdir -p /ishield-app && mkdir -p /ishield-app/public

RUN chgrp -R 0 /ishield-app && chmod -R g=u /ishield-app

COPY build/_bin/argocd-interlace /usr/local/bin/argocd-interlace

COPY rekor/rekor-cli /usr/local/bin/rekor-cli

WORKDIR /ishield-app
COPY scripts/generate_signedcm.sh /ishield-app/generate_signedcm.sh
COPY scripts/gpg-annotation-sign.sh /ishield-app/gpg-annotation-sign.sh
COPY scripts/x509-annotation-sign.sh /ishield-app/x509-annotation-sign.sh

RUN chmod +x /ishield-app/generate_signedcm.sh &&\
    chmod +x /ishield-app/gpg-annotation-sign.sh &&\
    chmod +x /ishield-app/x509-annotation-sign.sh

COPY yq /usr/bin/yq

RUN  chmod +x /usr/bin/yq

RUN yq -V

ENTRYPOINT ["argocd-interlace"]



