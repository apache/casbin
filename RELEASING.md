<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements. See the NOTICE file
distributed with this work for additional information
regarding copyright ownership. The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
-->

# Releasing Apache Casbin (Incubating) for Go

1. Select the reviewed commit. Confirm that its source can be built with the
   versions in go.mod and go.sum, including the reviewed Govaluate revision.
2. Create the release candidate tag at that commit. The Release workflow
   assembles two unsigned source archives and their SHA-512 sidecars as a
   workflow artifact. Independently extract and test both archives. Check
   that the archives contain the same files and required legal materials.
3. Sign the exact archives with the release manager's key from the project
   KEYS, stage them under the Casbin ASF dev distribution directory, and
   verify fresh public downloads before requesting the applicable votes.
4. Once both votes pass, promote the approved archives, checksums, and
   signatures to the ASF release distribution directory. Verify the copies
   before creating the final tag or GitHub Release.
5. Create the final tag at the approved commit. GitHub Actions does not publish
   or rebuild a release from this tag. From an empty module cache, verify the
   public version of github.com/casbin/casbin/v3 through the module proxy and
   build a consumer against the downloaded module. Keep the dependency
   versions in the voted source for that release.

6. Create the GitHub Release after verifying the tag and public module. Attach
   the promoted originals and link the Apache downloads, disclaimer, and vote
   results.
