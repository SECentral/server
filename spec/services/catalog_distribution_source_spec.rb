require "rails_helper"
require "tmpdir"

RSpec.describe CatalogDistributionSource do
  def add_catalog(directory, distribution: "example", major: "9")
    document = JSON.parse(File.binread(Rails.root.join("spec/fixtures/catalogs/v3.json")))
    document["catalog"]["platform"].merge!("distribution" => distribution, "major_version" => major)
    digest = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(document['catalog']))}"
    document["content_digest"] = digest
    record = {
      "review_record_version" => 1, "content_digest" => digest,
      "review" => { "date" => "2026-10-11", "scope" => %w[booleans ports] },
      "known_limitations" => ["Synthetic fixture"]
    }
    artifact = Pathname.new(directory).join("#{distribution}/#{major}/targeted/#{digest.delete_prefix('sha256:')}.json")
    artifact.dirname.mkpath
    artifact.binwrite(JSON.generate(document))
    review = artifact.sub_ext(".review.json")
    review.binwrite(JSON.generate(record))
    [document, record, artifact, review]
  end

  def with_source
    Dir.mktmpdir do |directory|
      yield directory, *add_catalog(directory)
    end
  end

  it "validates the checked-in catalog tree with its shared GPL license" do
    expect(Rails.root.join("catalogs/LICENSES/GPL-2.0-or-later.txt").binread).to include("GNU GENERAL PUBLIC LICENSE", "Version 2")
    expect(described_class.verify(Rails.root.join("catalogs")).supported_count).to be_positive
  end

  it "validates a minimal review sidecar without repeated facts or upstream research" do
    with_source do |directory|
      expect(described_class.verify(directory).supported_count).to eq(1)
    end
  end

  it "allows empty temporary sources in the generic verifier" do
    Dir.mktmpdir do |directory|
      expect(described_class.verify(directory).supported_count).to eq(0)
    end
  end

  it "accepts a nonempty review scope limited to supported artifact families" do
    with_source do |directory, _, record, _, review|
      record["review"]["scope"] = ["ports"]
      review.binwrite(JSON.generate(record))
      expect(described_class.verify(directory).supported_count).to eq(1)
    end
  end

  it "supports multiple distributions and major versions without framework changes" do
    with_source do |directory|
      add_catalog(directory, distribution: "another")
      add_catalog(directory, major: "10")
      expect(described_class.verify(directory).supported_count).to eq(3)
    end
  end

  it "rejects missing review records and orphan artifacts" do
    with_source do |directory, _, _, _, review|
      review.delete
      expect { described_class.verify(directory) }.to raise_error(described_class::Invalid, /lacks a review/)
    end
  end

  it "rejects orphan review records" do
    with_source do |directory, _, _, artifact|
      artifact.delete
      expect { described_class.verify(directory) }.to raise_error(described_class::Invalid)
    end
  end

  it "rejects corrupt catalogs through the authoritative validator" do
    with_source do |directory, document, _, artifact|
      document["catalog"]["families"]["ports"]["complete"] = false
      artifact.binwrite(JSON.generate(document))
      expect { described_class.verify(directory) }.to raise_error(described_class::Invalid, /incomplete/)
    end
  end

  it "rejects catalog digest mismatches" do
    with_source do |directory, document, _, artifact|
      document["content_digest"] = "sha256:" + "b" * 64
      artifact.binwrite(JSON.generate(document))
      expect { described_class.verify(directory) }.to raise_error(described_class::Invalid, /digest mismatch/)
    end
  end

  {
    "filename/digest mismatch" => ->(record) { record["content_digest"] = "sha256:" + "b" * 64 },
    "unsupported review record" => ->(record) { record["review_record_version"] = 999 },
    "unsupported review record version type" => ->(record) { record["review_record_version"] = "1" },
    "unsupported review record fractional version" => ->(record) { record["review_record_version"] = 1.0 },
    "review scope" => ->(record) { record["review"]["scope"] = ["modules"] },
    "missing review scope" => ->(record) { record["review"].delete("scope") },
    "empty review scope" => ->(record) { record["review"]["scope"] = [] },
    "duplicate review scope" => ->(record) { record["review"]["scope"] = %w[ports ports] },
    "review date" => ->(record) { record["review"].delete("date") },
    "invalid review date format" => ->(record) { record["review"]["date"] = "yesterday" }
  }.each do |message, mutate|
    it "rejects #{message}" do
      with_source do |directory, _, record, _, review|
        mutate.call(record)
        review.binwrite(JSON.generate(record))
        expect { described_class.verify(directory) }.to raise_error(described_class::Invalid)
      end
    end
  end

  it "rejects impossible review dates" do
    with_source do |directory, _, record, _, review|
      record["review"]["date"] = "2026-02-30"
      review.binwrite(JSON.generate(record))
      expect { described_class.verify(directory) }.to raise_error(described_class::Invalid, /date/)
    end
  end

  it "rejects unexpected portable metadata" do
    with_source do |directory, document, _, artifact|
      document["metadata"]["private_notes"] = "/private/path"
      artifact.binwrite(JSON.generate(document))
      expect { described_class.verify(directory) }.to raise_error(described_class::Invalid, /unreviewed metadata/)
    end
  end

  it "rejects layout that disagrees with the declared platform" do
    with_source do |directory, _, _, artifact, review|
      target = Pathname.new(directory).join("another/9/targeted")
      target.mkpath
      File.rename(artifact, target.join(artifact.basename))
      File.rename(review, target.join(review.basename))
      expect { described_class.verify(directory) }.to raise_error(described_class::Invalid, /layout\/platform mismatch/)
    end
  end

  it "rejects traversal in the artifact's declared layout identity" do
    with_source do |directory, document, record, artifact, review|
      document["catalog"]["platform"]["distribution"] = "../outside"
      digest = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(document['catalog']))}"
      document["content_digest"] = record["content_digest"] = digest
      artifact.delete
      review.delete
      artifact.dirname.join("#{digest.delete_prefix('sha256:')}.json").binwrite(JSON.generate(document))
      artifact.dirname.join("#{digest.delete_prefix('sha256:')}.review.json").binwrite(JSON.generate(record))
      expect { described_class.verify(directory) }.to raise_error(described_class::Invalid, /layout\/platform mismatch/)
    end
  end

  it "requires the digest-named adjacent artifact rather than searching elsewhere" do
    with_source do |directory, _, _, artifact|
      File.rename(artifact, artifact.dirname.join("other.json"))
      expect { described_class.verify(directory) }.to raise_error(described_class::Invalid)
    end
  end

  %i[artifact review].each do |kind|
    it "rejects #{kind} symlinks escaping the source tree" do
      with_source do |directory, _, _, artifact, review|
        Dir.mktmpdir do |outside|
          path = kind == :artifact ? artifact : review
          target = Pathname.new(outside).join(path.basename)
          target.binwrite(path.binread)
          path.delete
          File.symlink(target, path)
          expect { described_class.verify(directory) }.to raise_error(described_class::Invalid, /escapes source directory/)
        end
      end
    end
  end

  it "rejects duplicate JSON keys in review records" do
    with_source do |directory, _, _, _, review|
      review.binwrite('{"review_record_version":1,"review_record_version":1}')
      expect { described_class.verify(directory) }.to raise_error(described_class::Invalid, /duplicate/i)
    end
  end
end
